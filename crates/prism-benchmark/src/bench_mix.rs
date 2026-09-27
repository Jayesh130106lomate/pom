use std::sync::Arc;
use std::time::{Duration, Instant};
use crate::stats::BenchStats;
use prism_mix::{
    cover::CoverTrafficGenerator,
    metrics::MixMetrics,
    poisson::PoissonDelay,
    pool::MixPool,
    scheduler::PacketScheduler,
};

pub async fn run_mix_benchmarks(iters: usize) -> Vec<BenchStats> {
    let mut results = Vec::new();

    // 1. Poisson Delay Sampling
    let poisson = PoissonDelay::new(10.0);
    let mut samples = Vec::with_capacity(iters * 10);
    let sample_count = iters * 10;
    for _ in 0..sample_count {
        let start = Instant::now();
        let _ = poisson.sample();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Poisson Delay Sampling", samples, None));

    // 2. Cover Traffic Packet Generation (32KB)
    let cover_gen = CoverTrafficGenerator::new(5.0, 32768);
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = cover_gen.generate_drop_cover(32768);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Cover Traffic Generate (32KB)", samples, Some(32768)));

    // 3. MixPool Single Packet Insertion
    let mut pool = MixPool::new();
    let dummy_packet = vec![0xEEu8; 100];
    let mut samples = Vec::with_capacity(iters);
    for i in 0..iters {
        let delay = Duration::from_millis((i % 100) as u64 + 10);
        let p = dummy_packet.clone();
        let start = Instant::now();
        let _ = pool.insert(p, delay);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("MixPool Insert (100B pkt)", samples, Some(100)));

    // 4. MixPool Burst Insertion: 1,000 packets
    let burst_size = 1000;
    let burst_iters = (iters / 10).max(10);
    let mut samples = Vec::with_capacity(burst_iters);
    for _ in 0..burst_iters {
        let mut burst_pool = MixPool::new();
        let start = Instant::now();
        for j in 0..burst_size {
            let delay = Duration::from_millis((j % 50) as u64 + 5);
            let _ = burst_pool.insert(vec![0xAA; 64], delay);
        }
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("MixPool Burst Insert (1K pkts)", samples, Some(64 * burst_size)));

    // 5. MixPool Drain Ready
    let mut mature_pool = MixPool::new();
    mature_pool.set_min_pool_size(0);
    for _ in 0..1000 {
        let _ = mature_pool.insert(vec![0xBB; 64], Duration::from_nanos(1));
    }
    tokio::time::sleep(Duration::from_millis(5)).await;
    let mut samples = Vec::with_capacity(burst_iters);
    for _ in 0..burst_iters {
        // refill
        for _ in 0..200 {
            let _ = mature_pool.insert(vec![0xBB; 64], Duration::from_nanos(1));
        }
        let start = Instant::now();
        let drained = mature_pool.drain_ready();
        samples.push(start.elapsed().as_nanos() as u64);
        let _ = drained;
    }
    results.push(BenchStats::compute("MixPool Drain Ready Batch", samples, None));

    // 6. PacketScheduler Concurrency (schedule & retrieve across multiple tasks)
    let scheduler = Arc::new(PacketScheduler::new());
    let sched_count = (iters / 2).max(100);
    let mut samples = Vec::with_capacity(sched_count);

    for _ in 0..sched_count {
        let s = scheduler.clone();
        let start = Instant::now();
        s.schedule(vec![1, 2, 3], Duration::from_millis(1)).await;
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("PacketScheduler Schedule", samples, None));

    // 7. MixMetrics Recording
    let mut metrics = MixMetrics::new();
    let mut samples = Vec::with_capacity(iters * 5);
    for i in 0..(iters * 5) {
        let is_cover = i % 3 == 0;
        let start = Instant::now();
        metrics.record_packet(5.5, is_cover);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("MixMetrics Record Latency", samples, None));

    results
}
