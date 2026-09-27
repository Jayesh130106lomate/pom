use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;

use prism_transport::{
    generate_relay_cert, TransportClient, TransportConfig, TransportServer,
};

#[tokio::test]
async fn test_valid_relay_identity_handshake_succeeds() {
    let relay_seed = [0x11u8; 32];
    let server_config = TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size: 64,
        ..Default::default()
    };

    let server = TransportServer::new_with_identity(server_config, Some(&relay_seed))
        .expect("Server creation should succeed");
    let server_addr = server.local_addr().unwrap();
    let relay_identity = server.public_identity();

    let (tx, mut rx) = mpsc::channel(10);
    let server_handle = tokio::spawn(async move {
        let _ = server.run(tx).await;
    });

    let client = TransportClient::new(TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size: 64,
        ..Default::default()
    })
    .expect("Client creation should succeed");

    // Pin expected relay identity
    client.add_expected_relay(server_addr, relay_identity).await;

    let payload = vec![0xAA; 64];
    let send_res = client.send_packet(server_addr, &payload).await;
    assert!(send_res.is_ok(), "Send with matching identity MUST succeed: {:?}", send_res);

    let (sender, received) = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert_eq!(sender.ip(), server_addr.ip());
    assert_eq!(received, payload);

    client.shutdown();
    server_handle.abort();
}

#[tokio::test]
async fn test_impostor_relay_identity_mismatch_rejected() {
    // Legitimate relay has seed 0x22, but impostor runs with seed 0x33
    let legitimate_seed = [0x22u8; 32];
    let (_, _, legitimate_identity) = generate_relay_cert(Some(&legitimate_seed)).unwrap();

    let impostor_seed = [0x33u8; 32];
    let server_config = TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size: 64,
        ..Default::default()
    };

    let impostor_server = TransportServer::new_with_identity(server_config, Some(&impostor_seed))
        .expect("Impostor server creation");
    let impostor_addr = impostor_server.local_addr().unwrap();

    let (tx, _rx) = mpsc::channel(10);
    let server_handle = tokio::spawn(async move {
        let _ = impostor_server.run(tx).await;
    });

    let client = TransportClient::new(TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size: 64,
        ..Default::default()
    })
    .unwrap();

    // Client expects legitimate_identity at impostor_addr
    client.add_expected_relay(impostor_addr, legitimate_identity).await;

    let payload = vec![0xBB; 64];
    let send_res = client.send_packet(impostor_addr, &payload).await;

    assert!(
        send_res.is_err(),
        "Connection to impostor relay with mismatched identity MUST fail TLS verification"
    );

    let err_str = send_res.unwrap_err().to_string();
    assert!(
        err_str.contains("Connection failed") || err_str.contains("invalid certificate") || err_str.contains("InvalidCertificate"),
        "Error should reflect TLS connection failure, got: {}",
        err_str
    );

    client.shutdown();
    server_handle.abort();
}

#[tokio::test]
async fn test_multihop_pinned_circuit_transport() {
    let seeds = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let mut addrs = Vec::new();
    let mut identities = Vec::new();
    let mut rxs = Vec::new();
    let mut handles = Vec::new();

    for i in 0..3 {
        let conf = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            packet_size: 64,
            ..Default::default()
        };
        let s = TransportServer::new_with_identity(conf, Some(&seeds[i])).unwrap();
        let addr = s.local_addr().unwrap();
        let id = s.public_identity();
        let (tx, rx) = mpsc::channel(10);

        addrs.push(addr);
        identities.push(id);
        rxs.push(rx);

        let h = tokio::spawn(async move {
            let _ = s.run(tx).await;
        });
        handles.push(h);
    }

    let client = TransportClient::new(TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size: 64,
        ..Default::default()
    })
    .unwrap();

    // Register all 3 hops
    for i in 0..3 {
        client.add_expected_relay(addrs[i], identities[i]).await;
    }

    // Send packets sequentially mimicking hop-by-hop forwarding
    for i in 0..3 {
        let pkt = vec![(i as u8) + 1; 64];
        let res = client.send_packet(addrs[i], &pkt).await;
        assert!(res.is_ok(), "Hop {} send must succeed: {:?}", i + 1, res);

        let rec = tokio::time::timeout(Duration::from_secs(3), rxs[i].recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.1, pkt);
    }

    client.shutdown();
    for h in handles {
        h.abort();
    }
}

#[tokio::test]
async fn test_dos_connection_limit_and_admission_control() {
    let server_config = TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size: 64,
        max_connections: 2,
        max_connections_per_ip: 2,
        ..Default::default()
    };
    let server = TransportServer::new(server_config).unwrap();
    let server_addr = server.local_addr().unwrap();
    let metrics = server.metrics();

    let (tx, _rx) = mpsc::channel(10);
    let server_handle = tokio::spawn(async move {
        let _ = server.run(tx).await;
    });

    let client1 = TransportClient::new(TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size: 64,
        ..Default::default()
    }).unwrap();

    let client2 = TransportClient::new(TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size: 64,
        ..Default::default()
    }).unwrap();

    let client3 = TransportClient::new(TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size: 64,
        ..Default::default()
    }).unwrap();

    // Client 1 & 2 connect and hold
    let pkt = vec![0x11; 64];
    assert!(client1.send_packet(server_addr, &pkt).await.is_ok());
    assert!(client2.send_packet(server_addr, &pkt).await.is_ok());

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 2);

    // Client 3 exceeds per-IP / global limit of 2 -> rejected
    let res3 = client3.send_packet(server_addr, &pkt).await;
    assert!(res3.is_err(), "Exceeding connection limit must be rejected");

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        metrics.connections_rejected.load(Ordering::Relaxed) >= 1,
        "connections_rejected metric must increment"
    );

    client1.shutdown();
    client2.shutdown();
    client3.shutdown();
    server_handle.abort();
}

#[tokio::test]
async fn test_rate_limiter_packet_flood_drop_metrics() {
    let server_config = TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size: 64,
        max_connections: 10,
        rate_limit_per_ip_pps: 50.0,
        burst_factor: 1.0, // exactly 50 tokens max
        ..Default::default()
    };
    let server = TransportServer::new(server_config).unwrap();
    let server_addr = server.local_addr().unwrap();
    let metrics = server.metrics();

    let (tx, mut rx) = mpsc::channel(1000);
    let server_handle = tokio::spawn(async move {
        let _ = server.run(tx).await;
    });

    let client = TransportClient::new(TransportConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        packet_size: 64,
        ..Default::default()
    }).unwrap();

    // Flood 150 packets in rapid succession (burst capacity is only 50)
    let packets: Vec<Vec<u8>> = (0..150).map(|i| vec![i as u8; 64]).collect();
    let _ = client.send_packets_batch(server_addr, &packets).await;

    // Drain received
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut received_count = 0;
    while rx.try_recv().is_ok() {
        received_count += 1;
    }

    let dropped = metrics.packets_dropped_rate_limit.load(Ordering::Relaxed);
    assert!(
        dropped > 0,
        "Rate limiter must drop excess packets during flood. Dropped: {}, Received: {}",
        dropped,
        received_count
    );
    assert_eq!(
        received_count + dropped as usize,
        150,
        "Total processed packets must equal total sent packets"
    );

    client.shutdown();
    server_handle.abort();
}
