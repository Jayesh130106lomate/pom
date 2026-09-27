use std::time::Instant;
use crate::bench_sphinx::make_mock_route;
use crate::stats::BenchStats;
use prism_mix::pool::MixPool;
use prism_sphinx::{
    constants::PACKET_SIZE,
    packet::{create_sphinx_packet, process_sphinx_packet, SphinxPacket},
    replay::ReplayFilter,
};

pub struct StressReport {
    pub replay_detected: usize,
    pub replay_rate: f64,
    pub tampered_rejected: usize,
    pub tampered_rate: f64,
    pub pool_saturation_pkts: usize,
    pub pool_memory_estimate_kb: usize,
}

pub fn run_stress_benchmarks(flood_count: usize) -> (Vec<BenchStats>, StressReport) {
    let mut stats_list = Vec::new();

    // 1. Replay Flood Attack Resilience
    println!("Running Replay Attack Flood test ({} packets)...", flood_count);
    let mut filter = ReplayFilter::new(1024 * 1024, 7); // 1MB Bloom filter
    let secret = [0x5Au8; 32];
    let tag = ReplayFilter::derive_tag(&secret);
    filter.insert(&tag); // Initial insertion

    let mut replay_detected = 0;
    let mut replay_samples = Vec::with_capacity(flood_count);
    for _ in 0..flood_count {
        let start = Instant::now();
        if filter.insert(&tag) {
            replay_detected += 1;
        }
        replay_samples.push(start.elapsed().as_nanos() as u64);
    }
    let replay_rate = (replay_detected as f64 / flood_count as f64) * 100.0;
    let replay_stats = BenchStats::compute(
        "Stress: Replay Flood Defense Throughput",
        replay_samples,
        None,
    );
    stats_list.push(replay_stats.clone());

    // 2. Tampered / Corrupted Packet Rejection Flood
    println!("Running Corrupted Packet Flood test ({} packets)...", flood_count);
    let (route, sks) = make_mock_route(3);
    let valid_packet = create_sphinx_packet(b"secret payload", &route, 1).unwrap();
    let valid_bytes = valid_packet.to_bytes();

    let mut tampered_rejected = 0;
    let mut tamper_samples = Vec::with_capacity(flood_count);
    for i in 0..flood_count {
        let mut corrupted = valid_bytes.clone();
        // Corrupt header MAC (offset 37 + ROUTING_INFO_SIZE = 37 + 280 = 317)
        let corrupt_idx = (i % 32) + 317;
        corrupted[corrupt_idx] ^= 0xFF;

        let start = Instant::now();
        match SphinxPacket::from_bytes(&corrupted) {
            Ok(pkt) => {
                if process_sphinx_packet(&pkt, &sks[0]).is_err() {
                    tampered_rejected += 1;
                }
            }
            Err(_) => {
                tampered_rejected += 1;
            }
        }
        tamper_samples.push(start.elapsed().as_nanos() as u64);
    }
    let tampered_rate = (tampered_rejected as f64 / flood_count as f64) * 100.0;
    let tamper_stats = BenchStats::compute(
        "Stress: Tampered Packet Rejection Throughput",
        tamper_samples,
        Some(PACKET_SIZE),
    );
    stats_list.push(tamper_stats);

    // 3. Mix Pool Saturation & Memory Footprint under Flood
    println!("Running Mix Pool Memory Saturation test ({} packets)...", flood_count);
    let mut pool = MixPool::with_capacities(0, flood_count + 1000);
    let start = Instant::now();
    for _i in 0..flood_count {
        let packet_payload = vec![0xA5u8; 1024]; // 1KB packet chunk
        let _ = pool.insert(packet_payload, std::time::Duration::from_secs(60));
    }
    let saturation_elapsed = start.elapsed();
    let pool_saturation_pkts = pool.len();
    // Memory estimate: flood_count * (1024 bytes packet + BTreeMap node overhead ~64 bytes)
    let pool_memory_estimate_kb = (flood_count * (1024 + 64)) / 1024;

    let pool_samples = vec![saturation_elapsed.as_nanos() as u64 / flood_count as u64; flood_count];
    let pool_stats = BenchStats::compute(
        "Stress: MixPool Ingestion under Saturation",
        pool_samples,
        Some(1024),
    );
    stats_list.push(pool_stats);

    let report = StressReport {
        replay_detected,
        replay_rate,
        tampered_rejected,
        tampered_rate,
        pool_saturation_pkts,
        pool_memory_estimate_kb,
    };

    (stats_list, report)
}
