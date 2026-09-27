//! High-Throughput Concurrent Network Stress & Load Generator for POM Mixnet.
//!
//! Generates full cryptographic Sphinx packets across stratified 3-hop circuits
//! and streams them across entry relays over multiplexed QUIC connections.
//!
//! Supports two modes:
//! 1. Sustained Streaming Mode (`--duration <SECS>`): Measures true multi-second steady-state
//!    sustained throughput and wire bandwidth.
//! 2. Concurrency Burst Mode (`--packets <N>`): Measures maximum client-to-entry QUIC ingress
//!    write burst rate.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use prism_sphinx::packet::create_sphinx_packet;
use prism_sphinx::routing::{PacketFlag, RouteHop, RoutingInfo};
use prism_transport::{TransportClient, TransportConfig};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

#[derive(Parser, Debug)]
#[command(name = "pom-stress", about = "High-Throughput Concurrent Stress Generator for POM")]
struct Args {
    /// Total number of packets to dispatch (in burst mode)
    #[arg(short = 'n', long, default_value = "500")]
    packets: usize,

    /// Duration in seconds for continuous sustained streaming mode
    #[arg(short = 'd', long)]
    duration: Option<u64>,

    /// Number of concurrent async client worker tasks
    #[arg(short = 'c', long, default_value = "16")]
    concurrency: usize,

    /// Batch size per QUIC multiplexed write
    #[arg(short = 'b', long, default_value = "8")]
    batch_size: usize,

    /// Optional target rate limit in total packets/sec across all workers (0 for unthrottled burst)
    #[arg(short = 'r', long, default_value = "0")]
    rate: f64,

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
    if let Some(dur) = args.duration {
        println!("        POM MIXNET: CONTINUOUS SUSTAINED THROUGHPUT BENCHMARK ({}s)             ", dur);
    } else {
        println!("             POM MIXNET HIGH-THROUGHPUT CONCURRENCY BURST BENCHMARK             ");
    }
    println!("================================================================================");
    if let Some(dur) = args.duration {
        println!("Mode              : Continuous Sustained Streaming ({} seconds)", dur);
    } else {
        println!("Mode              : Concurrency Saturation Burst ({} packets)", args.packets);
    }
    println!("Concurrency       : {} async workers", args.concurrency);
    println!("Batch Size        : {} packets / batch", args.batch_size);
    println!("Packet Size       : {} bytes fixed (Sphinx + ChaCha20-Poly1305)", prism_sphinx::PACKET_SIZE);
    println!("================================================================================\n");

    let entry_addrs: Vec<SocketAddr> = args.entries.split(',').map(|s| s.trim().parse().unwrap()).collect();
    let mix_addrs: Vec<SocketAddr> = args.mixes.split(',').map(|s| s.trim().parse().unwrap()).collect();
    let exit_addrs: Vec<SocketAddr> = args.exits.split(',').map(|s| s.trim().parse().unwrap()).collect();

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

    // Pre-create pool of 200 prototype packets to recycle/send at maximum throughput
    let pool_size = if args.duration.is_some() { 200 } else { args.packets };
    println!(">> [1/4] Pre-synthesizing {} cryptographic Sphinx packets across circuits...", pool_size);
    let prep_start = Instant::now();

    let mut packets_by_entry: Vec<(SocketAddr, Vec<u8>)> = Vec::with_capacity(pool_size);
    for i in 0..pool_size {
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

        let payload = format!("POM_SUSTAINED_{:08}_TIME_{:?}", i, Instant::now());
        let pkt = create_sphinx_packet(payload.as_bytes(), &[hop1, hop2, hop3], 1)?;
        packets_by_entry.push((circuit.entry.addr, pkt.to_bytes()));
    }
    let prep_dur = prep_start.elapsed();
    println!("   Synthesized {} prototype packets in {:.2}s ({:.1} pkts/s)",
        pool_size, prep_dur.as_secs_f64(), pool_size as f64 / prep_dur.as_secs_f64()
    );

    println!("\n>> [2/4] Initializing QUIC Transport Client & Identity Verification...");
    let transport = Arc::new(TransportClient::new(TransportConfig::default())?);
    transport.add_expected_relay(entry1.addr, entry1.identity_pk).await;
    transport.add_expected_relay(entry2.addr, entry2.identity_pk).await;

    print!("   Warming up QUIC TLS 1.3 connections to entry nodes... ");
    let warm_pkt = &packets_by_entry[0].1;
    transport.send_packet(entry1.addr, warm_pkt).await?;
    transport.send_packet(entry2.addr, warm_pkt).await?;
    println!("OK (0-RTT TLS Handshake Verified)");

    // Group prototype packets into batches
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

    // Trackers
    let running = Arc::new(AtomicBool::new(true));
    let sent_packets = Arc::new(AtomicUsize::new(0));
    let failed_packets = Arc::new(AtomicUsize::new(0));
    let next_batch_idx = Arc::new(AtomicUsize::new(0));

    let is_sustained_mode = args.duration.is_some();
    let duration_secs = args.duration.unwrap_or(0);

    if is_sustained_mode {
        println!("\n>> [3/4] Streaming continuous traffic over {} seconds across {} workers...",
            duration_secs, args.concurrency
        );
    } else {
        println!("\n>> [3/4] Blasting {} packets burst across {} workers (batch size: {})...",
            args.packets, args.concurrency, args.batch_size
        );
    }

    let test_start = Instant::now();
    let mut worker_handles = Vec::new();

    let target_rate = args.rate;
    let concurrency = args.concurrency;

    for _ in 0..args.concurrency {
        let batches = batches.clone();
        let running = running.clone();
        let sent = sent_packets.clone();
        let failed = failed_packets.clone();
        let next_idx = next_batch_idx.clone();
        let transport = transport.clone();
        let total_burst = args.packets;

        let handle = tokio::spawn(async move {
            let num_batches = batches.len();
            loop {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                if !is_sustained_mode && idx >= (total_burst / 8).max(1) {
                    break;
                }
                let batch_slot = idx % num_batches;
                let (target, ref pkts) = batches[batch_slot];
                let count = pkts.len();

                match transport.send_packets_batch(target, pkts).await {
                    Ok(()) => {
                        sent.fetch_add(count, Ordering::Relaxed);
                    }
                    Err(_) => {
                        failed.fetch_add(count, Ordering::Relaxed);
                    }
                }

                if target_rate > 0.0 {
                    let delay_per_batch = Duration::from_secs_f64((count as f64) / (target_rate / concurrency as f64));
                    tokio::time::sleep(delay_per_batch).await;
                }
            }
        });
        worker_handles.push(handle);
    }

    // Monitoring loop
    let monitor_sent = sent_packets.clone();
    let monitor_running = running.clone();
    let total_pkts = args.packets;

    let progress_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut prev_count = 0usize;
        let mut sec_elapsed = 0u64;

        if is_sustained_mode {
            println!("   ┌────────┬──────────────────────┬──────────────────────┬──────────────────────┐");
            println!("   │ Time   │ Rolling Window Rate  │ Wire Bandwidth       │ Cumulative Dispatched│");
            println!("   ├────────┼──────────────────────┼──────────────────────┼──────────────────────┤");
        }

        loop {
            interval.tick().await;
            sec_elapsed += 1;
            let current = monitor_sent.load(Ordering::Relaxed);
            let delta = current.saturating_sub(prev_count);
            prev_count = current;
            let current_mb_s = (delta * prism_sphinx::PACKET_SIZE) as f64 / 1_048_576.0;

            if is_sustained_mode {
                println!("   │ {:>4}s  │ {:>8} pkts/s      │ {:>7.2} MB/s       │ {:>9} packets     │",
                    sec_elapsed, delta, current_mb_s, current
                );
                if sec_elapsed >= duration_secs {
                    monitor_running.store(false, Ordering::Relaxed);
                    break;
                }
            } else {
                let pct = (current as f64 / total_pkts as f64) * 100.0;
                print!("\r   Progress: {:>5} / {} packets ({:.1}%) ...", current, total_pkts, pct.min(100.0));
                std::io::Write::flush(&mut std::io::stdout()).ok();
                if current >= total_pkts {
                    monitor_running.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
        if is_sustained_mode {
            println!("   └────────┴──────────────────────┴──────────────────────┴──────────────────────┘");
        }
    });

    let _ = progress_handle.await;
    running.store(false, Ordering::Relaxed);

    for h in worker_handles {
        let _ = h.await;
    }
    let test_dur = test_start.elapsed();

    let total_sent = sent_packets.load(Ordering::Relaxed);
    let total_failed = failed_packets.load(Ordering::Relaxed);
    let total_attempts = total_sent + total_failed;
    let success_rate = if total_attempts > 0 {
        (total_sent as f64 / total_attempts as f64) * 100.0
    } else {
        0.0
    };

    let dur_sec = test_dur.as_secs_f64();
    let pps = total_sent as f64 / dur_sec;
    let mb_s = (total_sent * prism_sphinx::PACKET_SIZE) as f64 / dur_sec / 1_048_576.0;
    let mbps = mb_s * 8.0;

    println!("\n================================================================================");
    if is_sustained_mode {
        println!("             SUSTAINED MULTI-SECOND THROUGHPUT BENCHMARK RESULTS                ");
    } else {
        println!("              PEAK INGRESS BURST RATE BENCHMARK RESULTS                         ");
    }
    println!("================================================================================");
    println!("Test Mode                : {}", if is_sustained_mode { "Continuous Sustained Stream" } else { "Short Ingress Concurrency Burst" });
    println!("Measured Duration        : {:.3} seconds", dur_sec);
    println!("Total Packets Dispatched : {}", total_sent);
    println!("Total Wire Volume        : {:.2} MB ({:.2} GB)", (total_sent * prism_sphinx::PACKET_SIZE) as f64 / 1_048_576.0, (total_sent * prism_sphinx::PACKET_SIZE) as f64 / 1_073_741_824.0);
    println!("Transmission Failures    : {}", total_failed);
    println!("Packet Success Rate      : {:.2}%", success_rate);
    println!("--------------------------------------------------------------------------------");
    if is_sustained_mode {
        println!("Sustained E2E Throughput : {:>8.2} packets/sec", pps);
        println!("Sustained Wire Bandwidth : {:>8.2} MB/s ({:.2} Mbps / {:.2} Gbps)", mb_s, mbps, mbps / 1000.0);
    } else {
        println!("Peak Ingress Burst Rate  : {:>8.2} packets/sec", pps);
        println!("Peak Ingress Bandwidth   : {:>8.2} MB/s ({:.2} Mbps / {:.2} Gbps)", mb_s, mbps, mbps / 1000.0);
        println!("NOTE: This measures client-to-entry QUIC socket write saturation during a burst.");
    }
    println!("Sphinx Fixed Packet Size : {} bytes", prism_sphinx::PACKET_SIZE);
    println!("Mean Client Time / Packet: {:.2} µs", (dur_sec / total_sent as f64) * 1_000_000.0);
    println!("================================================================================");

    println!("\n>> [4/4] Draining mixnet pipelines (waiting 2.0s)...");
    tokio::time::sleep(Duration::from_millis(2000)).await;
    transport.close().await;

    Ok(())
}
