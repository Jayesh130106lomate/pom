//! # prism-transport
//!
//! QUIC-based transport layer for PRISM relay-to-relay and client-to-relay
//! communication. All Sphinx packets are transmitted over QUIC connections
//! for reliable, multiplexed, encrypted transport.

pub mod connection;
pub mod errors;

pub use connection::{
    extract_ed25519_pubkey, generate_relay_cert, RelayIdentityVerifier, TransportClient,
    TransportConfig, TransportMetrics, TransportServer,
};
pub use errors::TransportError;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_quic_transport_roundtrip() {
        let server_config = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            packet_size: 64,
            max_connections: 10,
            ..Default::default()
        };
        let server = TransportServer::new(server_config).unwrap();
        let server_addr = server.local_addr().unwrap();

        let (tx, mut rx) = mpsc::channel(10);
        tokio::spawn(async move {
            let _ = server.run(tx).await;
        });

        let client_config = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            packet_size: 64,
            max_connections: 10,
            ..Default::default()
        };
        let client = TransportClient::new(client_config).unwrap();

        let packet = vec![42u8; 64];
        client.send_packet(server_addr, &packet).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout receiving packet")
            .expect("channel closed");

        assert_eq!(received.1, packet);

        // Test connection reuse (second packet over pooled QUIC connection)
        let packet2 = vec![84u8; 64];
        client.send_packet(server_addr, &packet2).await.unwrap();

        let received2 = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout receiving second packet")
            .expect("channel closed");

        assert_eq!(received2.1, packet2);
    }

    #[tokio::test]
    async fn test_quic_transport_batch() {
        let server_config = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            packet_size: 64,
            max_connections: 10,
            ..Default::default()
        };
        let server = TransportServer::new(server_config).unwrap();
        let server_addr = server.local_addr().unwrap();

        let (tx, mut rx) = mpsc::channel(50);
        tokio::spawn(async move {
            let _ = server.run(tx).await;
        });

        let client = TransportClient::new(TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            packet_size: 64,
            max_connections: 10,
            ..Default::default()
        }).unwrap();

        let batch: Vec<Vec<u8>> = (0..5)
            .map(|i| vec![i as u8 + 10; 64])
            .collect();

        client.send_packets_batch(server_addr, &batch).await.unwrap();

        let mut received_bytes = Vec::new();
        for _ in 0..5 {
            let item = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .expect("timeout receiving batch packet")
                .expect("channel closed");
            received_bytes.push(item.1);
        }

        assert_eq!(received_bytes.len(), 5);
        for expected in &batch {
            assert!(received_bytes.contains(expected), "Batch item not received");
        }
    }
}
