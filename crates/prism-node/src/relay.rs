//! Relay processing pipeline.
//!
//! The relay receives Sphinx packets, processes them (strip one encryption layer,
//! verify MAC, check replay), applies Poisson mixing delay, then forwards.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use prism_mix::cover::CoverTrafficGenerator;
use prism_mix::poisson::{AdaptivePoissonDelay, PoissonDelay};
use prism_mix::pool::MixPool;
use prism_sphinx::packet::{create_cover_packet, ProcessedPacket, SphinxPacket};
use prism_sphinx::replay::ReplayFilter;
use prism_sphinx::routing::{PacketFlag, RouteHop, RoutingInfo};
use prism_transport::{TransportClient, TransportConfig};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::config::NodeConfig;
use crate::state::NodeState;

/// An outgoing packet queued in the MixPool.
#[derive(Debug, Clone)]
pub struct OutgoingPacket {
    pub next_hop: std::net::SocketAddr,
    pub packet_bytes: Vec<u8>,
}

/// The relay processing pipeline.
pub struct RelayProcessor {
    config: NodeConfig,
    state: Arc<NodeState>,
    replay_filter: Arc<Mutex<ReplayFilter>>,
    relay_secret_key: [u8; 32],
    poisson: PoissonDelay,
    adaptive_poisson: Option<AdaptivePoissonDelay>,
    cover_generator: Arc<CoverTrafficGenerator>,
    mix_pool: Arc<Mutex<MixPool<OutgoingPacket>>>,
    pool_notify: Arc<tokio::sync::Notify>,
    transport_client: Arc<TransportClient>,
}

impl RelayProcessor {
    /// Create a new relay processor.
    pub fn new(
        config: NodeConfig,
        relay_secret_key: [u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let poisson = PoissonDelay::new(config.mix_rate);
        let adaptive_poisson = if config.adaptive_mixing {
            let max_mu = config.max_mix_rate.unwrap_or(config.mix_rate * 10.0).max(config.mix_rate);
            let target_anon = config.target_anonymity_set.unwrap_or(config.min_pool_size.max(5));
            Some(AdaptivePoissonDelay::new(config.mix_rate, max_mu, target_anon))
        } else {
            None
        };
        let cover_generator = Arc::new(CoverTrafficGenerator::new(config.mix_rate, prism_sphinx::PACKET_SIZE));
        let replay_filter = Arc::new(Mutex::new(ReplayFilter::default_for_epoch()));
        let max_pool_cap = config.max_pool_capacity.unwrap_or(10_000);
        let mix_pool = Arc::new(Mutex::new(MixPool::with_capacities(config.min_pool_size, max_pool_cap)));
        let pool_notify = Arc::new(tokio::sync::Notify::new());
        let state = Arc::new(NodeState::new());

        let transport_config = TransportConfig {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            packet_size: prism_sphinx::PACKET_SIZE,
            max_connections: 256,
            ..Default::default()
        };
        let transport_client = Arc::new(TransportClient::new(transport_config)?);

        Ok(RelayProcessor {
            config,
            state,
            replay_filter,
            relay_secret_key,
            poisson,
            adaptive_poisson,
            cover_generator,
            mix_pool,
            pool_notify,
            transport_client,
        })
    }

    /// Unpeel a Sphinx packet cryptographically in-place (pure CPU work, zero locks, zero buffer cloning).
    pub fn unpeel_packet(
        packet_bytes: &[u8],
        relay_sk: &[u8; 32],
    ) -> Result<(u32, ProcessedPacket), (Option<u32>, prism_sphinx::SphinxError)> {
        let packet = match SphinxPacket::from_bytes(packet_bytes) {
            Ok(p) => p,
            Err(e) => return Err((None, e)),
        };
        let epoch_id = packet.header.epoch_id;
        match prism_sphinx::packet::process_sphinx_packet_in_place(packet, relay_sk) {
            Ok(processed) => Ok((epoch_id, processed)),
            Err(e) => Err((Some(epoch_id), e)),
        }
    }

    /// Get a reference to the node state for reporting.
    pub fn state(&self) -> Arc<NodeState> {
        self.state.clone()
    }

    /// Get reference to internal MixPool for inspection and testing.
    #[allow(dead_code)]
    pub fn mix_pool(&self) -> Arc<Mutex<MixPool<OutgoingPacket>>> {
        self.mix_pool.clone()
    }

    /// Process incoming packets from the receive channel.
    ///
    /// Core relay loop:
    /// 1. Receive packet
    /// 2. Process Sphinx header (strip layer, verify MAC)
    /// 3. Check rotating replay filter
    /// 4. Enqueue into prioritized MixPool with Poisson delay
    /// 5. Background drain task forwards mature packets meeting min_pool_size
    pub async fn run(
        &self,
        mut packet_rx: mpsc::Receiver<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        info!(
            "Relay processor started (layer={}, mix_rate={}, min_pool_size={})",
            self.config.layer, self.config.mix_rate, self.config.min_pool_size
        );

        let max_batch = self.config.batch_size.unwrap_or(64).max(1);

        // 1. Spawn background MixPool draining task
        let pool_drain = self.mix_pool.clone();
        let notify_drain = self.pool_notify.clone();
        let client_drain = self.transport_client.clone();
        let state_drain = self.state.clone();
        let drain_batch_size = max_batch;

        let drain_handle = tokio::spawn(async move {
            loop {
                // Drain mature packets respecting min_pool_size up to drain_batch_size
                let ready = {
                    let mut p = pool_drain.lock().await;
                    p.drain_ready_batch(drain_batch_size)
                };

                if !ready.is_empty() {
                    // Group outgoing packets by next_hop to utilize batch multiplexing
                    let mut by_target: std::collections::HashMap<std::net::SocketAddr, Vec<Vec<u8>>> =
                        std::collections::HashMap::new();
                    for pkt in ready {
                        by_target.entry(pkt.next_hop).or_default().push(pkt.packet_bytes);
                    }

                    for (target, pkts) in by_target {
                        let client = client_drain.clone();
                        let state = state_drain.clone();
                        let count = pkts.len();
                        tokio::spawn(async move {
                            let res = if count == 1 {
                                client.send_packet(target, &pkts[0]).await
                            } else {
                                client.send_packets_batch(target, &pkts).await
                            };
                            match res {
                                Ok(()) => {
                                    state.packets_forwarded.fetch_add(count as u64, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    error!("Failed to forward {} packets to {}: {}", count, target, e);
                                }
                            }
                        });
                    }
                }

                // Check deadline of next mature packet or wait for notification
                let sleep_dur = {
                    let p = pool_drain.lock().await;
                    if p.len() > p.min_pool_size() {
                        p.next_deadline().map(|d| {
                            let now = std::time::Instant::now();
                            if d > now { d - now } else { std::time::Duration::ZERO }
                        })
                    } else {
                        None
                    }
                };

                match sleep_dur {
                    Some(dur) => {
                        tokio::select! {
                            _ = tokio::time::sleep(dur) => {}
                            _ = notify_drain.notified() => {}
                        }
                    }
                    None => {
                        notify_drain.notified().await;
                    }
                }
            }
        });

        // 2. Spawn background automated Sphinx cover traffic generator
        let pool_cover = self.mix_pool.clone();
        let notify_cover = self.pool_notify.clone();
        let cover_gen = self.cover_generator.clone();
        let cover_listen_addr = self.config.listen_addr;
        let cover_target_addr = if cover_listen_addr.ip().is_unspecified() {
            std::net::SocketAddr::new(
                if cover_listen_addr.is_ipv6() {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                } else {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                },
                cover_listen_addr.port(),
            )
        } else {
            cover_listen_addr
        };
        let cover_epoch = self.config.epoch_id;
        let my_pk = *X25519Public::from(&X25519Secret::from(self.relay_secret_key)).as_bytes();

        let cover_handle = tokio::spawn(async move {
            loop {
                let delay = cover_gen.next_delay();
                tokio::time::sleep(delay).await;

                // Create a valid loop cover packet directed to self
                let hop = RouteHop {
                    routing: RoutingInfo {
                        next_hop: cover_target_addr,
                        delay_seed: 0,
                        flag: PacketFlag::LoopCover,
                        reserved: 0,
                    },
                    public_key: my_pk,
                };

                if let Ok(pkt) = create_cover_packet(&[hop], cover_epoch, PacketFlag::LoopCover) {
                    let bytes = pkt.to_bytes();
                    let pool_delay = cover_gen.next_delay();
                    let inserted = {
                        let mut p = pool_cover.lock().await;
                        p.insert(
                            OutgoingPacket {
                                next_hop: cover_target_addr,
                                packet_bytes: bytes,
                            },
                            pool_delay,
                        ).is_ok()
                    };
                    if inserted {
                        notify_cover.notify_one();
                    }
                }
            }
        });

        // 3. Main ingress packet reception loop with batching & parallel processing
        while let Some(first_item) = packet_rx.recv().await {
            let mut batch = Vec::with_capacity(max_batch);
            batch.push(first_item);

            // Drain any pending packets up to max_batch non-blockingly
            while batch.len() < max_batch {
                match packet_rx.try_recv() {
                    Ok(item) => batch.push(item),
                    Err(_) => break,
                }
            }

            self.state.packets_received.fetch_add(batch.len() as u64, Ordering::Relaxed);

            let relay_sk = self.relay_secret_key;
            let current_epoch = self.config.epoch_id;

            // Crypto unpeeling: inline if single packet, Rayon work-stealing parallel iter if batch > 1
            let unpeeled_results: Vec<Result<(u32, ProcessedPacket), (Option<u32>, prism_sphinx::SphinxError)>> = if batch.len() == 1 {
                let (_from, bytes) = batch.into_iter().next().unwrap();
                vec![Self::unpeel_packet(&bytes, &relay_sk)]
            } else {
                use rayon::prelude::*;
                tokio::task::spawn_blocking(move || {
                    batch
                        .into_par_iter()
                        .map(|(_from, bytes)| Self::unpeel_packet(&bytes, &relay_sk))
                        .collect()
                })
                .await
                .unwrap_or_default()
            };

            let mut valid_to_replay_check = Vec::with_capacity(unpeeled_results.len());

            for res in unpeeled_results {
                match res {
                    Ok((epoch_id, processed)) => {
                        if epoch_id != current_epoch {
                            warn!(
                                "Packet rejected: invalid epoch ID (got {}, expected {})",
                                epoch_id, current_epoch
                            );
                            continue;
                        }

                        let shared_secret = match &processed {
                            ProcessedPacket::Forward { shared_secret, .. } => *shared_secret,
                            ProcessedPacket::Destination { shared_secret, .. } => *shared_secret,
                            ProcessedPacket::LoopCover { shared_secret, .. } => *shared_secret,
                            ProcessedPacket::DropCover { shared_secret } => *shared_secret,
                        };

                        valid_to_replay_check.push((shared_secret, processed));
                    }
                    Err((_, prism_sphinx::SphinxError::MacVerificationFailed { .. })) => {
                        self.state.mac_failures.fetch_add(1, Ordering::Relaxed);
                        debug!("MAC verification failed");
                    }
                    Err((_, e)) => {
                        debug!("Sphinx processing error: {}", e);
                    }
                }
            }

            if valid_to_replay_check.is_empty() {
                continue;
            }

            // Batch replay check with single lock acquisition
            let mut valid_processed = Vec::with_capacity(valid_to_replay_check.len());
            {
                let mut filter = self.replay_filter.lock().await;
                for (shared_secret, processed) in valid_to_replay_check {
                    if filter.check_and_insert(&shared_secret).is_err() {
                        self.state.replays_detected.fetch_add(1, Ordering::Relaxed);
                        debug!("Replay detected");
                    } else {
                        valid_processed.push(processed);
                    }
                }
            }

            if valid_processed.is_empty() {
                continue;
            }

            // Route packets
            let mut outgoing_items = Vec::new();
            for processed in valid_processed {
                match processed {
                    ProcessedPacket::Forward {
                        next_hop,
                        delay_seed: _,
                        packet: next_packet,
                        ..
                    } => {
                        outgoing_items.push((next_hop, next_packet.to_bytes()));
                    }
                    ProcessedPacket::LoopCover {
                        next_hop,
                        delay_seed: _,
                        packet: next_packet,
                        ..
                    } => {
                        let is_self = next_hop == self.config.listen_addr
                            || next_hop.ip().is_unspecified()
                            || (next_hop.ip().is_loopback() && (self.config.listen_addr.ip().is_unspecified() || self.config.listen_addr.ip().is_loopback()) && next_hop.port() == self.config.listen_addr.port());
                        if is_self {
                            debug!("Loop cover completed round trip to originator");
                            self.state.packets_dropped.fetch_add(1, Ordering::Relaxed);
                        } else {
                            outgoing_items.push((next_hop, next_packet.to_bytes()));
                        }
                    }
                    ProcessedPacket::Destination { payload, .. } => {
                        let msg_str = String::from_utf8_lossy(&payload);
                        info!(
                            "Received message at destination ({} bytes): \"{}\"",
                            payload.len(),
                            msg_str
                        );
                        println!("\n╔════════════════════════════════════════════════════════════════════════╗");
                        println!("║ [PRISM EXIT RELAY] Received & Decrypted Final Payload                 ║");
                        println!("╠════════════════════════════════════════════════════════════════════════╣");
                        println!("║ Payload Size   : {:<53} ║", format!("{} bytes", payload.len()));
                        println!("║ Plaintext      : {:<53} ║", msg_str);
                        println!("╚════════════════════════════════════════════════════════════════════════╝\n");
                        self.state.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                    }
                    ProcessedPacket::DropCover { .. } => {
                        debug!("Dropping cover traffic packet");
                        self.state.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            // Batch insert into MixPool with single lock acquisition
            if !outgoing_items.is_empty() {
                let mut inserted_any = false;
                {
                    let mut pool = self.mix_pool.lock().await;
                    for (i, (next_hop, packet_bytes)) in outgoing_items.into_iter().enumerate() {
                        let cur_depth = pool.len() + i;
                        let delay = if let Some(ref adaptive) = self.adaptive_poisson {
                            adaptive.sample_smoothed(cur_depth)
                        } else {
                            self.poisson.sample()
                        };
                        match pool.insert(OutgoingPacket { next_hop, packet_bytes }, delay) {
                            Ok(()) => {
                                inserted_any = true;
                            }
                            Err(prism_mix::pool::PoolError::CapacityExceeded { current, max }) => {
                                self.state.pool_overflow_drops.fetch_add(1, Ordering::Relaxed);
                                warn!(
                                    "MixPool overflow: capacity exceeded ({}/{}), shedding packet destined to {}",
                                    current, max, next_hop
                                );
                            }
                        }
                    }
                }
                if inserted_any {
                    self.pool_notify.notify_one();
                }
            }
        }

        drain_handle.abort();
        cover_handle.abort();
        info!("Relay processor stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use prism_sphinx::packet::create_sphinx_packet;
    use prism_sphinx::routing::{PacketFlag, RouteHop, RoutingInfo};
    use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

    fn setup_relay(epoch_id: u32) -> (RelayProcessor, [u8; 32], [u8; 32]) {
        let relay_sk = X25519Secret::random_from_rng(rand::thread_rng());
        let relay_pk = X25519Public::from(&relay_sk);

        let config = NodeConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            layer: 1,
            mix_rate: 100.0,
            min_pool_size: 1,
            epoch_id,
            max_packet_rate: 3000,
            key_path: "relay_keys.json".into(),
            adaptive_mixing: false,
            max_mix_rate: None,
            target_anonymity_set: None,
            batch_size: None,
            max_pool_capacity: None,
        };

        let processor = RelayProcessor::new(config, relay_sk.to_bytes()).unwrap();
        (processor, relay_sk.to_bytes(), relay_pk.to_bytes())
    }

    fn make_packet(relay_pk: &[u8; 32], epoch_id: u32) -> SphinxPacket {
        let hop = RouteHop {
            routing: RoutingInfo {
                next_hop: "127.0.0.1:9099".parse().unwrap(),
                delay_seed: 0,
                flag: PacketFlag::FinalHop,
                reserved: 0,
            },
            public_key: *relay_pk,
        };
        create_sphinx_packet(b"adversarial relay processing test payload", &[hop], epoch_id).unwrap()
    }

    #[tokio::test]
    async fn test_relay_wire_tampered_epoch_id_accounted_as_mac_failure() {
        let (processor, _sk, pk) = setup_relay(1);
        let state = processor.state();

        let (tx, rx) = mpsc::channel(10);
        let handle = tokio::spawn(async move {
            processor.run(rx).await;
        });

        // Legitimate packet created for epoch 1
        let packet = make_packet(&pk, 1);
        let mut wire_bytes = packet.to_bytes();

        // Adversary tampers with epoch_id on wire: modifies bytes 1..5
        wire_bytes[1] ^= 0x01; // changes epoch from 1 to 2 or higher

        let sender: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        tx.send((sender, wire_bytes)).await.unwrap();

        // Wait briefly for relay to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(state.packets_received.load(Ordering::Relaxed), 1);
        assert_eq!(
            state.mac_failures.load(Ordering::Relaxed),
            1,
            "Wire-tampered epoch_id MUST increment mac_failures counter"
        );
        assert_eq!(state.packets_forwarded.load(Ordering::Relaxed), 0);

        drop(tx);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_relay_wire_tampered_epoch_matching_config_epoch_accounted_as_mac_failure() {
        let (processor, _sk, pk) = setup_relay(1);
        let state = processor.state();

        let (tx, rx) = mpsc::channel(10);
        let handle = tokio::spawn(async move {
            processor.run(rx).await;
        });

        // Client created packet for epoch 2
        let packet = make_packet(&pk, 2);
        let mut wire_bytes = packet.to_bytes();

        // Adversary on wire changes epoch_id from 2 to 1 (matching relay's config.epoch_id = 1)
        wire_bytes[1..5].copy_from_slice(&1u32.to_be_bytes());

        let sender: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        tx.send((sender, wire_bytes)).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(state.packets_received.load(Ordering::Relaxed), 1);
        assert_eq!(
            state.mac_failures.load(Ordering::Relaxed),
            1,
            "Altered epoch_id matching config.epoch_id MUST still fail MAC and increment mac_failures"
        );
        assert_eq!(state.packets_forwarded.load(Ordering::Relaxed), 0);

        drop(tx);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_relay_legitimate_wrong_epoch_not_accounted_as_mac_failure() {
        let (processor, _sk, pk) = setup_relay(1);
        let state = processor.state();

        let (tx, rx) = mpsc::channel(10);
        let handle = tokio::spawn(async move {
            processor.run(rx).await;
        });

        // Legitimate packet created for epoch 2 (valid MAC for epoch 2, no wire tampering)
        let packet = make_packet(&pk, 2);
        let wire_bytes = packet.to_bytes();

        let sender: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        tx.send((sender, wire_bytes)).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(state.packets_received.load(Ordering::Relaxed), 1);
        assert_eq!(
            state.mac_failures.load(Ordering::Relaxed),
            0,
            "Valid packet from another epoch has valid MAC, so mac_failures MUST NOT increment"
        );
        assert_eq!(
            state.packets_forwarded.load(Ordering::Relaxed),
            0,
            "Packet rejected due to invalid epoch MUST NOT be forwarded"
        );

        drop(tx);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_relay_legitimate_packet_processed_and_delivered() {
        let (processor, _sk, pk) = setup_relay(1);
        let state = processor.state();

        let (tx, rx) = mpsc::channel(10);
        let handle = tokio::spawn(async move {
            processor.run(rx).await;
        });

        // Legitimate packet for epoch 1
        let packet = make_packet(&pk, 1);
        let wire_bytes = packet.to_bytes();

        let sender: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        tx.send((sender, wire_bytes)).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(state.packets_received.load(Ordering::Relaxed), 1);
        assert_eq!(state.mac_failures.load(Ordering::Relaxed), 0);
        assert_eq!(state.packets_forwarded.load(Ordering::Relaxed), 1);

        drop(tx);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_relay_malformed_truncated_packet_not_mac_failure() {
        let (processor, _sk, _pk) = setup_relay(1);
        let state = processor.state();

        let (tx, rx) = mpsc::channel(10);
        let handle = tokio::spawn(async move {
            processor.run(rx).await;
        });

        // Send 100 bytes (malformed packet)
        let malformed = vec![0xEEu8; 100];
        let sender: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        tx.send((sender, malformed)).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(state.packets_received.load(Ordering::Relaxed), 1);
        assert_eq!(
            state.mac_failures.load(Ordering::Relaxed),
            0,
            "Malformed deserialization error is NOT a MAC failure"
        );
        assert_eq!(state.packets_forwarded.load(Ordering::Relaxed), 0);

        drop(tx);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_relay_replay_detection_after_successful_mac() {
        let (processor, _sk, pk) = setup_relay(1);
        let state = processor.state();

        let (tx, rx) = mpsc::channel(10);
        let handle = tokio::spawn(async move {
            processor.run(rx).await;
        });

        let packet = make_packet(&pk, 1);
        let wire_bytes = packet.to_bytes();
        let sender: SocketAddr = "127.0.0.1:1111".parse().unwrap();

        // Send once
        tx.send((sender, wire_bytes.clone())).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(state.packets_forwarded.load(Ordering::Relaxed), 1);
        assert_eq!(state.replays_detected.load(Ordering::Relaxed), 0);

        // Send duplicate (replay)
        tx.send((sender, wire_bytes)).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(state.replays_detected.load(Ordering::Relaxed), 1);
        assert_eq!(state.mac_failures.load(Ordering::Relaxed), 0);
        assert_eq!(state.packets_forwarded.load(Ordering::Relaxed), 1);

        drop(tx);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_relay_mixpool_threshold_and_draining() {
        let (processor, _sk, pk) = setup_relay(1);
        let pool = processor.mix_pool();

        // Enforce min_pool_size = 3
        {
            let mut p = pool.lock().await;
            p.set_min_pool_size(3);
        }

        let (tx, rx) = mpsc::channel(10);
        let handle = tokio::spawn(async move {
            processor.run(rx).await;
        });

        // Create forward hop packet
        let hop1 = RouteHop {
            routing: RoutingInfo {
                next_hop: "127.0.0.1:9099".parse().unwrap(),
                delay_seed: 0,
                flag: PacketFlag::Forward,
                reserved: 0,
            },
            public_key: pk,
        };
        let hop2 = RouteHop {
            routing: RoutingInfo {
                next_hop: "127.0.0.1:9098".parse().unwrap(),
                delay_seed: 0,
                flag: PacketFlag::FinalHop,
                reserved: 0,
            },
            public_key: pk,
        };
        let packet = create_sphinx_packet(b"mixpool threshold test", &[hop1, hop2], 1).unwrap();
        let wire_bytes = packet.to_bytes();
        let sender: SocketAddr = "127.0.0.1:1111".parse().unwrap();

        // Send 1st packet -> pool size = 1 <= min_pool_size (3) -> should remain in pool
        tx.send((sender, wire_bytes.clone())).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        {
            let p = pool.lock().await;
            assert!(p.len() >= 1, "Packets must be held in MixPool");
            assert!(p.len() <= 3, "MixPool must not exceed min_pool_size without draining");
        }

        drop(tx);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_relay_loop_cover_termination_at_home() {
        let (processor, _sk, pk) = setup_relay(1);
        let state = processor.state();

        let (tx, rx) = mpsc::channel(10);
        let handle = tokio::spawn(async move {
            processor.run(rx).await;
        });

        // Loop cover packet with next_hop = relay's listen_addr (returning home)
        let hop = RouteHop {
            routing: RoutingInfo {
                next_hop: "127.0.0.1:0".parse().unwrap(),
                delay_seed: 0,
                flag: PacketFlag::LoopCover,
                reserved: 0,
            },
            public_key: pk,
        };
        let packet = create_cover_packet(&[hop], 1, PacketFlag::LoopCover).unwrap();
        let wire_bytes = packet.to_bytes();

        let sender: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        tx.send((sender, wire_bytes)).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(state.packets_received.load(Ordering::Relaxed), 1);
        assert_eq!(state.mac_failures.load(Ordering::Relaxed), 0);
        assert_eq!(
            state.packets_dropped.load(Ordering::Relaxed),
            1,
            "Loop cover packet arriving back at home relay must be recorded as dropped/completed"
        );

        drop(tx);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_relay_mixpool_overflow_shedding() {
        let relay_sk = X25519Secret::random_from_rng(rand::thread_rng());
        let relay_pk = X25519Public::from(&relay_sk);

        // Bounded capacity of exactly 1 packet in MixPool
        let config = NodeConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            layer: 1,
            mix_rate: 0.001, // very slow so packet stays in pool
            min_pool_size: 5,
            epoch_id: 1,
            max_packet_rate: 3000,
            key_path: "relay_keys.json".into(),
            adaptive_mixing: false,
            max_mix_rate: None,
            target_anonymity_set: None,
            batch_size: None,
            max_pool_capacity: Some(1),
        };

        let processor = RelayProcessor::new(config, relay_sk.to_bytes()).unwrap();
        let state = processor.state();

        let (tx, rx) = mpsc::channel(10);
        let handle = tokio::spawn(async move {
            processor.run(rx).await;
        });

        let hop1 = RouteHop {
            routing: RoutingInfo {
                next_hop: "127.0.0.1:9099".parse().unwrap(),
                delay_seed: 0,
                flag: PacketFlag::Forward,
                reserved: 0,
            },
            public_key: relay_pk.to_bytes(),
        };
        let hop2 = RouteHop {
            routing: RoutingInfo {
                next_hop: "127.0.0.1:9098".parse().unwrap(),
                delay_seed: 0,
                flag: PacketFlag::FinalHop,
                reserved: 0,
            },
            public_key: relay_pk.to_bytes(),
        };

        let pkt1 = create_sphinx_packet(b"packet 1 in pool", &[hop1.clone(), hop2.clone()], 1).unwrap();
        let pkt2 = create_sphinx_packet(b"packet 2 in pool", &[hop1, hop2], 1).unwrap();

        let sender: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        tx.send((sender, pkt1.to_bytes())).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 2nd packet exceeds capacity 1 -> should be shed
        tx.send((sender, pkt2.to_bytes())).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(state.packets_received.load(Ordering::Relaxed), 2);
        assert_eq!(
            state.pool_overflow_drops.load(Ordering::Relaxed),
            1,
            "Second packet must be shed and recorded as pool_overflow_drops"
        );

        drop(tx);
        let _ = handle.await;
    }
}
