use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use crate::stats::BenchStats;
use prism_transport::{TransportClient, TransportConfig, TransportServer};

pub async fn run_transport_benchmarks(iters: usize) -> Vec<BenchStats> {
    let mut results = Vec::new();
    let packet_size = 32_768; // 32 KB fixed Sphinx packet size

    // 1. Setup local QUIC server
    let server_config = TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size,
        max_connections: 512,
        ..Default::default()
    };
    let server = TransportServer::new(server_config).expect("bind transport server");
    let server_addr = server.local_addr().expect("get local addr");

    let (packet_tx, mut packet_rx) = mpsc::channel::<(std::net::SocketAddr, Vec<u8>)>(10_000);
    let server_handle = tokio::spawn(async move {
        let _ = server.run(packet_tx).await;
    });

    let client_config = TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size,
        max_connections: 512,
        ..Default::default()
    };
    let client = Arc::new(TransportClient::new(client_config).expect("create transport client"));
    let dummy_packet = vec![0x3Cu8; packet_size];

    // 2. Measure Cold Connection Latency (First packet to new endpoint)
    let cold_iters = (iters / 10).clamp(5, 20);
    let mut cold_samples = Vec::with_capacity(cold_iters);
    for _ in 0..cold_iters {
        // Create fresh server and client for cold test
        let c_srv_cfg = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            packet_size,
            max_connections: 10,
            ..Default::default()
        };
        let c_srv = TransportServer::new(c_srv_cfg).unwrap();
        let c_addr = c_srv.local_addr().unwrap();
        let (c_tx, mut c_rx) = mpsc::channel(10);
        let s_task = tokio::spawn(async move {
            let _ = c_srv.run(c_tx).await;
        });

        let fresh_client = TransportClient::new(TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            packet_size,
            max_connections: 10,
            ..Default::default()
        }).unwrap();

        let start = Instant::now();
        fresh_client.send_packet(c_addr, &dummy_packet).await.unwrap();
        let _ = c_rx.recv().await.unwrap();
        cold_samples.push(start.elapsed().as_nanos() as u64);

        fresh_client.shutdown();
        s_task.abort();
    }
    results.push(BenchStats::compute(
        "QUIC Cold Handshake + 32KB Transfer",
        cold_samples,
        Some(packet_size),
    ));

    // 3. Warm Pooled Connection Roundtrip Latency (Send -> Recv on server)
    // Warm up connection first
    client.send_packet(server_addr, &dummy_packet).await.unwrap();
    let _ = packet_rx.recv().await.unwrap();

    let warm_iters = iters.max(50);
    let mut warm_samples = Vec::with_capacity(warm_iters);
    for _ in 0..warm_iters {
        let start = Instant::now();
        client.send_packet(server_addr, &dummy_packet).await.unwrap();
        let _ = packet_rx.recv().await.unwrap();
        warm_samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute(
        "QUIC Pooled Warm Send+Recv (32KB)",
        warm_samples,
        Some(packet_size),
    ));

    // 4. Concurrent Client Transfers (10 concurrent workers sending to server)
    let concurrent_workers = 10;
    let packets_per_worker = (warm_iters / concurrent_workers).max(10);
    let total_concurrent = concurrent_workers * packets_per_worker;

    let start = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..concurrent_workers {
        let cl = client.clone();
        let pkt = dummy_packet.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..packets_per_worker {
                cl.send_packet(server_addr, &pkt).await.unwrap();
            }
        }));
    }

    let mut recv_count = 0;
    while recv_count < total_concurrent {
        if packet_rx.recv().await.is_some() {
            recv_count += 1;
        }
    }
    for h in handles {
        h.await.unwrap();
    }
    let concurrent_duration = start.elapsed();

    let concurrent_samples = vec![concurrent_duration.as_nanos() as u64 / total_concurrent as u64; total_concurrent];
    results.push(BenchStats::compute(
        &format!("QUIC Concurrent Send ({} workers, 32KB)", concurrent_workers),
        concurrent_samples,
        Some(packet_size),
    ));

    // Cleanup
    client.shutdown();
    server_handle.abort();

    results
}
