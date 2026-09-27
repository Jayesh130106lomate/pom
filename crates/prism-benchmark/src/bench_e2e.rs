use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, Mutex};
use crate::stats::BenchStats;
use prism_mix::poisson::PoissonDelay;
use prism_sphinx::{
    constants::PACKET_SIZE,
    packet::{create_sphinx_packet, process_sphinx_packet, ProcessedPacket, SphinxPacket},
    replay::ReplayFilter,
    routing::{PacketFlag, RouteHop, RoutingInfo},
};
use prism_transport::{TransportClient, TransportConfig, TransportServer};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

struct RelayInstance {
    pub server_addr: std::net::SocketAddr,
    pub server_handle: tokio::task::JoinHandle<()>,
    pub processor_handle: tokio::task::JoinHandle<()>,
}

async fn start_relay(
    sk: [u8; 32],
    epoch_id: u32,
    mix_rate: f64,
    dest_tx: Option<mpsc::Sender<Vec<u8>>>,
) -> RelayInstance {
    let srv_cfg = TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size: PACKET_SIZE,
        max_connections: 256,
        ..Default::default()
    };
    let server = TransportServer::new(srv_cfg).unwrap();
    let server_addr = server.local_addr().unwrap();

    let (packet_tx, mut packet_rx) = mpsc::channel::<(std::net::SocketAddr, Vec<u8>)>(1000);
    let server_handle = tokio::spawn(async move {
        let _ = server.run(packet_tx).await;
    });

    let client = Arc::new(
        TransportClient::new(TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            packet_size: PACKET_SIZE,
            max_connections: 256,
            ..Default::default()
        })
        .unwrap(),
    );

    let replay_filter = Arc::new(Mutex::new(ReplayFilter::new(65536, 7)));
    let poisson = PoissonDelay::new(mix_rate);

    let processor_handle = tokio::spawn(async move {
        while let Some((_from, packet_bytes)) = packet_rx.recv().await {
            let packet = match SphinxPacket::from_bytes(&packet_bytes) {
                Ok(p) => p,
                Err(_) => continue,
            };

            if packet.header.epoch_id != epoch_id {
                continue;
            }

            let processed = match process_sphinx_packet(&packet, &sk) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let shared_secret = match &processed {
                ProcessedPacket::Forward { shared_secret, .. } => *shared_secret,
                ProcessedPacket::Destination { shared_secret, .. } => *shared_secret,
                _ => continue,
            };

            {
                let mut filter = replay_filter.lock().await;
                if filter.check_and_insert(&shared_secret).is_err() {
                    continue; // Replay detected!
                }
            }

            match processed {
                ProcessedPacket::Forward { next_hop, packet: next_pkt, .. } => {
                    let delay = poisson.sample();
                    let client = client.clone();
                    let next_bytes = next_pkt.to_bytes();
                    tokio::spawn(async move {
                        if delay.as_millis() > 0 {
                            tokio::time::sleep(delay).await;
                        }
                        let _ = client.send_packet(next_hop, &next_bytes).await;
                    });
                }
                ProcessedPacket::Destination { payload, .. } => {
                    if let Some(tx) = &dest_tx {
                        let _ = tx.send(payload).await;
                    }
                }
                _ => {}
            }
        }
    });

    RelayInstance {
        server_addr,
        server_handle,
        processor_handle,
    }
}

pub async fn run_e2e_benchmarks(num_packets: usize) -> Vec<BenchStats> {
    let mut results = Vec::new();
    let epoch_id = 1u32;
    // Mix rate = 100.0 (mean delay = 10ms for benchmark responsiveness)
    let mix_rate = 100.0;

    let sk1 = X25519Secret::random_from_rng(rand::thread_rng());
    let pk1 = X25519Public::from(&sk1);
    let sk2 = X25519Secret::random_from_rng(rand::thread_rng());
    let pk2 = X25519Public::from(&sk2);
    let sk3 = X25519Secret::random_from_rng(rand::thread_rng());
    let pk3 = X25519Public::from(&sk3);

    let (dest_tx, mut dest_rx) = mpsc::channel::<Vec<u8>>(1000);

    let relay3 = start_relay(sk3.to_bytes(), epoch_id, mix_rate, Some(dest_tx)).await;
    let relay2 = start_relay(sk2.to_bytes(), epoch_id, mix_rate, None).await;
    let relay1 = start_relay(sk1.to_bytes(), epoch_id, mix_rate, None).await;

    let route = vec![
        RouteHop {
            routing: RoutingInfo {
                next_hop: relay2.server_addr,
                delay_seed: 1,
                flag: PacketFlag::Forward,
                reserved: 0,
            },
            public_key: pk1.to_bytes(),
        },
        RouteHop {
            routing: RoutingInfo {
                next_hop: relay3.server_addr,
                delay_seed: 2,
                flag: PacketFlag::Forward,
                reserved: 0,
            },
            public_key: pk2.to_bytes(),
        },
        RouteHop {
            routing: RoutingInfo {
                next_hop: "127.0.0.1:9999".parse().unwrap(),
                delay_seed: 3,
                flag: PacketFlag::FinalHop,
                reserved: 0,
            },
            public_key: pk3.to_bytes(),
        },
    ];

    let client = Arc::new(
        TransportClient::new(TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            packet_size: PACKET_SIZE,
            max_connections: 256,
            ..Default::default()
        })
        .unwrap(),
    );

    let test_count = num_packets.clamp(10, 100);
    let test_msg = b"PRISM mixnet end-to-end benchmark test payload content 1234567890";

    let mut latencies_ns = Vec::with_capacity(test_count);
    let delivered_count = Arc::new(AtomicUsize::new(0));

    // Send packets sequentially or in a slight pipeline and measure end-to-end delivery
    for i in 0..test_count {
        let pkt = create_sphinx_packet(test_msg, &route, epoch_id).unwrap();
        let pkt_bytes = pkt.to_bytes();

        let start = Instant::now();
        client.send_packet(relay1.server_addr, &pkt_bytes).await.unwrap();

        match tokio::time::timeout(std::time::Duration::from_secs(3), dest_rx.recv()).await {
            Ok(Some(delivered)) => {
                let elapsed = start.elapsed().as_nanos() as u64;
                assert_eq!(&delivered[..], test_msg, "Payload corrupted in transit!");
                latencies_ns.push(elapsed);
                delivered_count.fetch_add(1, Ordering::Relaxed);
            }
            Ok(None) => panic!("Destination channel closed unexpectedly"),
            Err(_) => {
                eprintln!("Packet {} timed out waiting for delivery", i);
            }
        }
    }

    let success_rate = (delivered_count.load(Ordering::Relaxed) as f64 / test_count as f64) * 100.0;
    println!(
        "E2E Mixnet: Delivered {}/{} packets ({:.1}% reliability) through 3-hop QUIC pipeline",
        delivered_count.load(Ordering::Relaxed),
        test_count,
        success_rate
    );

    results.push(BenchStats::compute(
        "E2E 3-Hop Mixnet Pipeline Delivery",
        latencies_ns,
        Some(PACKET_SIZE),
    ));

    // Cleanup
    client.shutdown();
    relay1.server_handle.abort();
    relay1.processor_handle.abort();
    relay2.server_handle.abort();
    relay2.processor_handle.abort();
    relay3.server_handle.abort();
    relay3.processor_handle.abort();

    results
}
