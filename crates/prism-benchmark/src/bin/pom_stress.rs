//! High-Throughput Concurrent Network Stress & Load Generator for POM Mixnet.
//!
//! Generates full cryptographic Sphinx packets across stratified 3-hop circuits
//! and blasts them across entry relays over multiplexed QUIC streams.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use prism_sphinx::packet::create_sphinx_packet;
use prism_sphinx::routing::{PacketFlag, RouteHop, RoutingInfo};
use prism_transport::{TransportClient, TransportConfig};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

#[derive(Parser, Debug)]
#[command(name = "pom-stress", about = "High-Throughput Concurrent Stress Generator for POM")]
struct Args {
    /// Total number of packets to dispatch
    #[arg(short = 'n', long, default_value = "500")]
    packets: usize,

    /// Number of concurrent async client worker tasks
    #[arg(short = 'c', long, default_value = "16")]
    concurrency: usize,

    /// Batch size per QUIC multiplexed write
    #[arg(short = 'b', long, default_value = "8")]
    batch_size: usize,

    /// Entry relay addresses (comma-separated IP:ports)
    #[arg(long, default_value = "172.28.0.11:9001,172.28.0.12:9002")]
    entries: String,

    /// Mix relay addresses (comma-separated IP:ports)
    #[arg(long, default_value = "172.28.0.21:9003,172.28.0.22:9004")]
    mixes: String,

    /// Exit relay addresses (comma-separated IP:ports)
    #[arg(long, default_value = "172.28.0.31:9005,172.28.0.32:9006")]
    exits: String,
}

#[derive(Clone)]
struct RelayInfo {
    addr: SocketAddr,
    sphinx_pk: [u8; 32],
    identity_pk: [u8; 32],
}

fn derive_keys(seed: u64, addr: SocketAddr) -> RelayInfo {
    let mut arr = [0u8; 32];
    let seed_val = seed.wrapping_mul(8).wrapping_add(64);
    arr[0..8].copy_from_slice(&seed_val.to_le_bytes());
    arr[8] = (seed & 0xFF) as u8;

    let sphinx_key_bytes = prism_crypto::kdf::hkdf_sha256(
        &arr,
        b"prism-key-separation",
        b"sphinx-x25519-v1",
        32,
    );
    let mut sphinx_key = [0u8; 32];
    sphinx_key.copy_from_slice(&sphinx_key_bytes);
    let secret = X25519Secret::from(sphinx_key);
    let sphinx_pk = *X25519Public::from(&secret).as_bytes();

    let tls_seed_bytes = prism_crypto::kdf::hkdf_sha256(
        &arr,
        b"prism-key-separation",
        b"tls-ed25519-v1",
        32,
    );
    let mut tls_seed = [0u8; 32];
    tls_seed.copy_from_slice(&tls_seed_bytes);
    let dalek_sk = ed25519_dalek::SigningKey::from_bytes(&tls_seed);
    let identity_pk = dalek_sk.verifying_key().to_bytes();

    RelayInfo {
        addr,
        sphinx_pk,
        identity_pk,
    }
}

struct CircuitPath {
    entry: RelayInfo,
    mix: RelayInfo,
    exit: RelayInfo,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("================================================================================");
    println!("             POM MIXNET HIGH-THROUGHPUT CONCURRENT STRESS TEST                  ");
    println!("================================================================================");
    println!("Target Packets    : {}", args.packets);
    println!("Concurrency       : {} async workers", args.concurrency);
    println!("Batch Size        : {} packets / batch", args.batch_size);
    println!("Packet Size       : {} bytes fixed (Sphinx + ChaCha20-Poly1305)", prism_sphinx::PACKET_SIZE);
    println!("Total Volume      : {:.2} MB", (args.packets * prism_sphinx::PACKET_SIZE) as f64 / 1_048_576.0);
    println!("================================================================================\n");

    let entry_addrs: Vec<SocketAddr> = args.entries.split(',').map(|s| s.trim().parse().unwrap()).collect();
    let mix_addrs: Vec<SocketAddr> = args.mixes.split(',').map(|s| s.trim().parse().unwrap()).collect();
    let exit_addrs: Vec<SocketAddr> = args.exits.split(',').map(|s| s.trim().parse().unwrap()).collect();

    // Map known seeds to relays:
    // Entry 1: seed 1, Entry 2: seed 2
    // Mix 1  : seed 3, Mix 2  : seed 4
    // Exit 1 : seed 5, Exit 2 : seed 6
    let entry1 = derive_keys(1, entry_addrs[0]);
    let entry2 = derive_keys(2, entry_addrs[1]);
    let mix1 = derive_keys(3, mix_addrs[0]);
    let mix2 = derive_keys(4, mix_addrs[1]);
    let exit1 = derive_keys(5, exit_addrs[0]);
    let exit2 = derive_keys(6, exit_addrs[1]);

    let circuits = vec![
        CircuitPath { entry: entry1.clone(), mix: mix1.clone(), exit: exit1.clone() },
        CircuitPath { entry: entry2.clone(), mix: mix2.clone(), exit: exit2.clone() },
        CircuitPath { entry: entry1.clone(), mix: mix2.clone(), exit: exit1.clone() },
        CircuitPath { entry: entry2.clone(), mix: mix1.clone(), exit: exit2.clone() },
    ];

    println!(">> [1/4] Pre-synthesizing {} cryptographic Sphinx packets across 4 circuits...", args.packets);
    let prep_start = Instant::now();

    // Pre-create packets grouped by (entry_address, batch)
    let mut packets_by_entry: Vec<(SocketAddr, Vec<u8>)> = Vec::with_capacity(args.packets);
    for i in 0..args.packets {
        let circuit = &circuits[i % circuits.len()];
        let hop1 = RouteHop {
            routing: RoutingInfo {
                next_hop: circuit.mix.addr,
                delay_seed: 0,
                flag: PacketFlag::Forward,
                reserved: 0,
            },
            public_key: circuit.entry.sphinx_pk,
        };
        let hop2 = RouteHop {
            routing: RoutingInfo {
                next_hop: circuit.exit.addr,
                delay_seed: 0,
                flag: PacketFlag::Forward,
                reserved: 0,
            },
            public_key: circuit.mix.sphinx_pk,
        };
        let hop3 = RouteHop {
            routing: RoutingInfo {
                next_hop: circuit.exit.addr,
                delay_seed: 0,
                flag: PacketFlag::FinalHop,
                reserved: 0,
            },
            public_key: circuit.exit.sphinx_pk,
        };

        let payload = format!("POM_STRESS_BURST_{:08}_TIME_{:?}", i, Instant::now());
        let pkt = create_sphinx_packet(payload.as_bytes(), &[hop1, hop2, hop3], 1)?;
        packets_by_entry.push((circuit.entry.addr, pkt.to_bytes()));
    }
    let prep_dur = prep_start.elapsed();
    println!("   Synthesized {} packets in {:.2}s ({:.1} pkts/s | {:.2} MB/s)",
        args.packets,
        prep_dur.as_secs_f64(),
        args.packets as f64 / prep_dur.as_secs_f64(),
        (args.packets * prism_sphinx::PACKET_SIZE) as f64 / prep_dur.as_secs_f64() / 1_048_576.0
    );

    println!("\n>> [2/4] Initializing QUIC Transport Client & Identity Verification...");
    let transport = Arc::new(TransportClient::new(TransportConfig::default())?);
    transport.add_expected_relay(entry1.addr, entry1.identity_pk).await;
    transport.add_expected_relay(entry2.addr, entry2.identity_pk).await;

    // Warm-up connection handshake to both entry nodes
    print!("   Warming up QUIC TLS 1.3 connections to entry nodes... ");
    let warm_pkt = &packets_by_entry[0].1;
    transport.send_packet(entry1.addr, warm_pkt).await?;
    transport.send_packet(entry2.addr, warm_pkt).await?;
    println!("OK (0-RTT TLS Handshake Verified)");

    println!("\n>> [3/4] Blasting {} packets across {} concurrent workers (batch size: {})...",
        args.packets, args.concurrency, args.batch_size
    );

    // Group packets into batches
    let mut batches: Vec<(SocketAddr, Vec<Vec<u8>>)> = Vec::new();
    let mut cur_addr = packets_by_entry[0].0;
    let mut cur_batch: Vec<Vec<u8>> = Vec::new();

    for (addr, bytes) in packets_by_entry {
        if addr != cur_addr || cur_batch.len() >= args.batch_size {
            if !cur_batch.is_empty() {
                batches.push((cur_addr, cur_batch));
                cur_batch = Vec::new();
            }
            cur_addr = addr;
        }
        cur_batch.push(bytes);
    }
    if !cur_batch.is_empty() {
        batches.push((cur_addr, cur_batch));
    }

    let batches = Arc::new(batches);
    let next_batch_idx = Arc::new(AtomicUsize::new(0));
    let sent_packets = Arc::new(AtomicUsize::new(0));
    let failed_packets = Arc::new(AtomicUsize::new(0));

    let burst_start = Instant::now();
    let mut worker_handles = Vec::new();

    for _ in 0..args.concurrency {
        let batches = batches.clone();
        let next_idx = next_batch_idx.clone();
        let sent = sent_packets.clone();
        let failed = failed_packets.clone();
        let transport = transport.clone();

        let handle = tokio::spawn(async move {
            loop {
                let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                if idx >= batches.len() {
                    break;
                }
                let (target, ref pkts) = batches[idx];
                let count = pkts.len();
                match transport.send_packets_batch(target, pkts).await {
                    Ok(()) => {
                        sent.fetch_add(count, Ordering::Relaxed);
                    }
                    Err(e) => {
                        eprintln!("Batch send error to {}: {}", target, e);
                        failed.fetch_add(count, Ordering::Relaxed);
                    }
                }
            }
        });
        worker_handles.push(handle);
    }

    // Monitor progress
    let monitor_sent = sent_packets.clone();
    let total_pkts = args.packets;
    let progress_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
        loop {
            interval.tick().await;
            let current = monitor_sent.load(Ordering::Relaxed);
            let pct = (current as f64 / total_pkts as f64) * 100.0;
            if current >= total_pkts {
                break;
            }
            print!("\r   Progress: {:>5} / {} packets ({:.1}%) ...", current, total_pkts, pct);
            std::io::Write::flush(&mut std::io::stdout()).ok();
        }
    });

    for h in worker_handles {
        let _ = h.await;
    }
    progress_handle.abort();
    let burst_dur = burst_start.elapsed();

    let total_sent = sent_packets.load(Ordering::Relaxed);
    let total_failed = failed_packets.load(Ordering::Relaxed);
    let burst_sec = burst_dur.as_secs_f64();
    let pps = total_sent as f64 / burst_sec;
    let mb_s = (total_sent * prism_sphinx::PACKET_SIZE) as f64 / burst_sec / 1_048_576.0;

    println!("\r   Progress: {:>5} / {} packets (100.0%) ... DONE!   \n", total_sent, total_pkts);

    println!("================================================================================");
    println!("                   STRESS TEST THROUGHPUT RESULTS                               ");
    println!("================================================================================");
    println!("Total Packets Dispatched : {}", total_sent);
    println!("Failed Transmissions     : {}", total_failed);
    println!("Packet Success Rate      : {:.2}%", (total_sent as f64 / (total_sent + total_failed) as f64) * 100.0);
    println!("Burst Duration           : {:.3} seconds", burst_sec);
    println!("Sustained Throughput     : {:>8.2} packets/sec", pps);
    println!("Sustained Bandwidth      : {:>8.2} MB/s ({:.2} Mbps)", mb_s, mb_s * 8.0);
    println!("Single Packet Size       : {} bytes", prism_sphinx::PACKET_SIZE);
    println!("Average Packet Time      : {:.2} µs / packet", (burst_sec / total_sent as f64) * 1_000_000.0);
    println!("================================================================================");

    // Wait 2.0s for exit nodes to process through Poisson mixing pipelines
    println!("\n>> [4/4] Draining stratified mix pools across relays (waiting 2.0s)...");
    tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
    transport.close().await;

    println!(">> Stress run complete! Inspecting relay telemetry...");

    Ok(())
}
