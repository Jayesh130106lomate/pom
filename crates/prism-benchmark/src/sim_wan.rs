//! WAN and Network-Impairment Simulation for PRISM.
//!
//! Evaluates the PRISM protocol and Sphinx packet processing under realistic
//! wide-area network (WAN) impairments beyond local loopback:
//! - Packet loss tiers: 1%, 5%, 10%, 15%
//! - Asymmetric latency: Uplink (20–40 ms) vs. Downlink (50–100 ms)
//! - Gaussian packet jitter (σ = 15 ms)
//! - Out-of-order delivery queue and reordering dynamics
//! - Temporary relay blackout / network outage (500 ms) and recovery time

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::time::Instant;
use rand::Rng;
use rand_distr::{Distribution, Normal};
use serde::{Deserialize, Serialize};

use crate::stats::BenchStats;
use prism_sphinx::constants::PACKET_SIZE;
use prism_sphinx::packet::{create_sphinx_packet, process_sphinx_packet_in_place, ProcessedPacket};
use prism_sphinx::routing::{PacketFlag, RouteHop, RoutingInfo};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Configuration for WAN channel simulation.
#[derive(Debug, Clone)]
pub struct WanConfig {
    pub name: String,
    pub packet_loss_rate: f64,
    pub uplink_latency_range_ms: (f64, f64),
    pub downlink_latency_range_ms: (f64, f64),
    pub jitter_sigma_ms: f64,
    pub blackout_duration_ms: Option<f64>,
    pub blackout_start_pct: Option<f64>,
}

/// Simulated delivery event in the WAN channel.
#[derive(Debug)]
struct ScheduledPacket {
    delivery_time_ms: f64,
    packet_id: usize,
    payload_bytes: Vec<u8>,
    #[allow(dead_code)]
    was_delayed_by_blackout: bool,
}

impl PartialEq for ScheduledPacket {
    fn eq(&self, other: &Self) -> bool {
        self.delivery_time_ms == other.delivery_time_ms && self.packet_id == other.packet_id
    }
}

impl Eq for ScheduledPacket {}

impl PartialOrd for ScheduledPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Min-heap ordering by delivery time
impl Ord for ScheduledPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        other.delivery_time_ms.partial_cmp(&self.delivery_time_ms).unwrap_or(Ordering::Equal)
    }
}

/// Results of a WAN impairment evaluation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanTestResult {
    pub name: String,
    pub total_packets_sent: usize,
    pub packets_delivered: usize,
    pub packets_dropped: usize,
    pub delivery_rate_pct: f64,
    pub retransmissions_required: usize,
    pub out_of_order_packets: usize,
    pub reorder_rate_pct: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub throughput_mb_s: f64,
    pub recovery_time_ms: Option<f64>,
    pub blackout_queued_packets: usize,
}

impl WanTestResult {
    pub fn format_markdown_row(&self) -> String {
        let rec_str = match self.recovery_time_ms {
            Some(ms) => format!("{:.1} ms", ms),
            None => "-".to_string(),
        };
        format!(
            "| {:<24} | {:>7.1}% | {:>8.1} ms | {:>8.1} ms | {:>8.1} ms | {:>7.1}% | {:>10.2} MB/s | {:>9} |",
            self.name,
            self.delivery_rate_pct,
            self.p50_latency_ms,
            self.p95_latency_ms,
            self.p99_latency_ms,
            self.reorder_rate_pct,
            self.throughput_mb_s,
            rec_str
        )
    }
}

/// Realistic WAN Channel Model.
pub struct WanChannelModel {
    config: WanConfig,
}

impl WanChannelModel {
    pub fn new(config: WanConfig) -> Self {
        Self { config }
    }

    /// Execute multi-hop Sphinx transmission across the impaired channel.
    pub fn simulate_flow(
        &self,
        packets: &[Vec<u8>],
        route_hops: &[([u8; 32], [u8; 32])], // (sk, pk)
    ) -> (WanTestResult, Vec<u64>) {
        let mut rng = rand::thread_rng();
        let normal = Normal::new(0.0, self.config.jitter_sigma_ms).unwrap();
        let num_packets = packets.len();

        let mut queue: BinaryHeap<ScheduledPacket> = BinaryHeap::new();
        let mut packets_dropped = 0;
        let mut retransmissions_required = 0;
        let mut blackout_queued = 0;

        let total_flow_duration_est_ms = num_packets as f64 * 5.0;
        let blackout_window = if let (Some(dur), Some(start_pct)) = (
            self.config.blackout_duration_ms,
            self.config.blackout_start_pct,
        ) {
            let start = total_flow_duration_est_ms * start_pct;
            Some((start, start + dur))
        } else {
            None
        };

        let mut max_blackout_delay = 0.0f64;

        // 1. Ingress scheduling across WAN uplink
        for (i, pkt_bytes) in packets.iter().enumerate() {
            let send_time_ms = i as f64 * 4.0; // 250 pkts/s injection rate

            // Check packet loss
            if self.config.packet_loss_rate > 0.0 && rng.gen_bool(self.config.packet_loss_rate) {
                packets_dropped += 1;
                // Under transport retransmission (e.g. QUIC stream loss recovery):
                // 1 packet loss requires ~1 RTT retransmission
                retransmissions_required += 1;
                continue;
            }

            // Asymmetric Latency: Uplink + Downlink + Jitter across 3 hops
            let uplink_base = rng.gen_range(self.config.uplink_latency_range_ms.0..self.config.uplink_latency_range_ms.1);
            let downlink_base = rng.gen_range(self.config.downlink_latency_range_ms.0..self.config.downlink_latency_range_ms.1);
            let jitter: f64 = normal.sample(&mut rng);

            let hop_transit_latency = (uplink_base + downlink_base + jitter).max(10.0);
            let mut arrival_time = send_time_ms + hop_transit_latency;

            let mut was_blackout = false;
            if let Some((b_start, b_end)) = blackout_window {
                if arrival_time >= b_start && arrival_time < b_end {
                    // Packet buffered during outage
                    blackout_queued += 1;
                    let extra_delay = b_end - arrival_time + rng.gen_range(1.0..10.0);
                    arrival_time += extra_delay;
                    max_blackout_delay = max_blackout_delay.max(extra_delay);
                    was_blackout = true;
                }
            }

            queue.push(ScheduledPacket {
                delivery_time_ms: arrival_time,
                packet_id: i,
                payload_bytes: pkt_bytes.clone(),
                was_delayed_by_blackout: was_blackout,
            });
        }

        // 2. Deliver packets in arrival order (reordering simulation)
        let mut delivered = 0;
        let mut last_delivered_id: Option<usize> = None;
        let mut out_of_order_count = 0;
        let mut latencies_ns = Vec::with_capacity(queue.len());
        let start_time_instant = Instant::now();

        while let Some(sched) = queue.pop() {
            // Cryptographic unpeeling at the receiving relay hops
            let mut cur_packet = prism_sphinx::packet::SphinxPacket::from_bytes(&sched.payload_bytes)
                .expect("valid sphinx packet");

            let mut unpeeled_ok = true;
            for (hop_idx, (sk, _pk)) in route_hops.iter().enumerate() {
                match process_sphinx_packet_in_place(cur_packet, sk) {
                    Ok(ProcessedPacket::Forward { packet: next_p, .. }) => {
                        cur_packet = next_p;
                    }
                    Ok(ProcessedPacket::Destination { payload, .. }) => {
                        if hop_idx != route_hops.len() - 1 || payload.is_empty() {
                            unpeeled_ok = false;
                        }
                        break;
                    }
                    _ => {
                        unpeeled_ok = false;
                        break;
                    }
                }
            }

            if unpeeled_ok {
                delivered += 1;
                let lat_ns = (sched.delivery_time_ms * 1_000_000.0) as u64;
                latencies_ns.push(lat_ns);

                if let Some(last_id) = last_delivered_id {
                    if sched.packet_id < last_id {
                        out_of_order_count += 1;
                    }
                }
                last_delivered_id = Some(sched.packet_id);
            }
        }

        let elapsed_secs = start_time_instant.elapsed().as_secs_f64().max(0.001);
        let delivery_rate_pct = if num_packets > 0 {
            (delivered as f64 / num_packets as f64) * 100.0
        } else {
            0.0
        };

        let reorder_rate_pct = if delivered > 0 {
            (out_of_order_count as f64 / delivered as f64) * 100.0
        } else {
            0.0
        };

        let mut sorted_lats = latencies_ns.clone();
        sorted_lats.sort_unstable();

        let p50 = if !sorted_lats.is_empty() {
            sorted_lats[sorted_lats.len() / 2] as f64 / 1_000_000.0
        } else {
            0.0
        };

        let p95 = if !sorted_lats.is_empty() {
            let idx = ((sorted_lats.len() as f64 * 0.95).round() as usize).min(sorted_lats.len() - 1);
            sorted_lats[idx] as f64 / 1_000_000.0
        } else {
            0.0
        };

        let p99 = if !sorted_lats.is_empty() {
            let idx = ((sorted_lats.len() as f64 * 0.99).round() as usize).min(sorted_lats.len() - 1);
            sorted_lats[idx] as f64 / 1_000_000.0
        } else {
            0.0
        };

        let total_bytes = delivered * PACKET_SIZE;
        let throughput_mb_s = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed_secs;

        let recovery_time = if self.config.blackout_duration_ms.is_some() {
            Some(max_blackout_delay)
        } else {
            None
        };

        let result = WanTestResult {
            name: self.config.name.clone(),
            total_packets_sent: num_packets,
            packets_delivered: delivered,
            packets_dropped,
            delivery_rate_pct,
            retransmissions_required,
            out_of_order_packets: out_of_order_count,
            reorder_rate_pct,
            p50_latency_ms: p50,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
            throughput_mb_s,
            recovery_time_ms: recovery_time,
            blackout_queued_packets: blackout_queued,
        };

        (result, latencies_ns)
    }
}

/// Run the full suite of WAN and network impairment benchmarks.
pub fn run_wan_benchmarks(num_packets: usize) -> Vec<BenchStats> {
    let test_count = num_packets.clamp(50, 500);

    // 1. Setup a standard 3-hop circuit for simulation
    let sk1 = X25519Secret::random_from_rng(rand::thread_rng());
    let pk1 = X25519Public::from(&sk1);
    let sk2 = X25519Secret::random_from_rng(rand::thread_rng());
    let pk2 = X25519Public::from(&sk2);
    let sk3 = X25519Secret::random_from_rng(rand::thread_rng());
    let pk3 = X25519Public::from(&sk3);

    let route_hops_keys = vec![
        (sk1.to_bytes(), pk1.to_bytes()),
        (sk2.to_bytes(), pk2.to_bytes()),
        (sk3.to_bytes(), pk3.to_bytes()),
    ];

    let route = vec![
        RouteHop {
            routing: RoutingInfo {
                next_hop: "192.0.2.2:9002".parse().unwrap(),
                delay_seed: 1,
                flag: PacketFlag::Forward,
                reserved: 0,
            },
            public_key: pk1.to_bytes(),
        },
        RouteHop {
            routing: RoutingInfo {
                next_hop: "192.0.2.3:9003".parse().unwrap(),
                delay_seed: 2,
                flag: PacketFlag::Forward,
                reserved: 0,
            },
            public_key: pk2.to_bytes(),
        },
        RouteHop {
            routing: RoutingInfo {
                next_hop: "192.0.2.4:9004".parse().unwrap(),
                delay_seed: 3,
                flag: PacketFlag::FinalHop,
                reserved: 0,
            },
            public_key: pk3.to_bytes(),
        },
    ];

    // Pre-construct valid 32 KB Sphinx packets
    let sample_payload = b"PRISM WAN Network-Impairment Benchmark Packet Payload Validated";
    let packets: Vec<Vec<u8>> = (0..test_count)
        .map(|_| {
            let pkt = create_sphinx_packet(sample_payload, &route, 1).unwrap();
            pkt.to_bytes()
        })
        .collect();

    // Define Impairment Tiers
    let tiers = vec![
        WanConfig {
            name: "Tier 0 (Ideal Loopback)".to_string(),
            packet_loss_rate: 0.0,
            uplink_latency_range_ms: (0.1, 0.5),
            downlink_latency_range_ms: (0.1, 0.5),
            jitter_sigma_ms: 0.1,
            blackout_duration_ms: None,
            blackout_start_pct: None,
        },
        WanConfig {
            name: "Tier 1 (Mild WAN: 1% Loss)".to_string(),
            packet_loss_rate: 0.01,
            uplink_latency_range_ms: (20.0, 30.0),
            downlink_latency_range_ms: (50.0, 70.0),
            jitter_sigma_ms: 5.0,
            blackout_duration_ms: None,
            blackout_start_pct: None,
        },
        WanConfig {
            name: "Tier 2 (Mod. WAN: 5% Loss)".to_string(),
            packet_loss_rate: 0.05,
            uplink_latency_range_ms: (20.0, 40.0),
            downlink_latency_range_ms: (50.0, 90.0),
            jitter_sigma_ms: 10.0,
            blackout_duration_ms: None,
            blackout_start_pct: None,
        },
        WanConfig {
            name: "Tier 3 (Lossy WAN: 10% Loss)".to_string(),
            packet_loss_rate: 0.10,
            uplink_latency_range_ms: (25.0, 45.0),
            downlink_latency_range_ms: (60.0, 100.0),
            jitter_sigma_ms: 15.0,
            blackout_duration_ms: None,
            blackout_start_pct: None,
        },
        WanConfig {
            name: "Tier 4 (Severe WAN: 15% Loss)".to_string(),
            packet_loss_rate: 0.15,
            uplink_latency_range_ms: (30.0, 50.0),
            downlink_latency_range_ms: (70.0, 120.0),
            jitter_sigma_ms: 15.0,
            blackout_duration_ms: None,
            blackout_start_pct: None,
        },
        WanConfig {
            name: "Tier 5 (500ms Blackout Outage)".to_string(),
            packet_loss_rate: 0.02,
            uplink_latency_range_ms: (20.0, 40.0),
            downlink_latency_range_ms: (50.0, 80.0),
            jitter_sigma_ms: 15.0,
            blackout_duration_ms: Some(500.0),
            blackout_start_pct: Some(0.40),
        },
    ];

    println!("\n### 9. WAN & Real-World Network Impairment Evaluation");
    println!(
        "| {:<24} | {:>8} | {:>11} | {:>11} | {:>11} | {:>9} | {:>13} | {:>9} |",
        "Impairment Tier", "Delivery", "p50 Latency", "p95 Latency", "p99 Latency", "Reordered", "Throughput", "Recovery"
    );
    println!(
        "|:{:-<24}-|-{:-<8}:|-{:-<11}:|-{:-<11}:|-{:-<11}:|-{:-<9}:|-{:-<13}:|-{:-<9}:|",
        "", "", "", "", "", "", "", ""
    );

    let mut bench_stats_list = Vec::new();

    for cfg in tiers {
        let model = WanChannelModel::new(cfg);
        let (result, latencies_ns) = model.simulate_flow(&packets, &route_hops_keys);
        println!("{}", result.format_markdown_row());

        let stats = BenchStats::compute(
            &format!("WAN Impairment: {}", result.name),
            latencies_ns,
            Some(PACKET_SIZE),
        );
        bench_stats_list.push(stats);
    }

    bench_stats_list
}
