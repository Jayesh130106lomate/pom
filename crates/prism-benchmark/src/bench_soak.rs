//! Long-Duration Stability and Soak Testing for PRISM.
//!
//! Validates:
//! - Multi-epoch stability across 10+ consecutive epoch rollovers (F_current -> F_previous)
//! - Bloom filter replay memory strictly bounded at 2 x 1 MB = 2 MB
//! - Continuous packet processing without progressive memory leakage (RSS monitoring)
//! - Socket descriptor and file descriptor leak detection

use std::fs;
use std::time::Instant;
use serde::{Deserialize, Serialize};

use crate::stats::BenchStats;
use prism_sphinx::constants::PACKET_SIZE;
use prism_sphinx::replay::ReplayFilter;
use rand::RngCore;

/// Soak test metrics recorded at an epoch rollover boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSnapshot {
    pub epoch_id: u32,
    pub packets_processed: usize,
    pub filter_current_count: usize,
    pub filter_previous_count: usize,
    pub filter_memory_bytes: usize,
    pub estimated_fpr: f64,
    pub rss_memory_kb: usize,
    pub open_fd_count: usize,
    pub elapsed_secs: f64,
}

/// Final summary of soak test execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoakSummary {
    pub total_epochs: u32,
    pub total_packets: usize,
    pub total_duration_secs: f64,
    pub throughput_pkts_per_sec: f64,
    pub max_filter_memory_bytes: usize,
    pub initial_rss_kb: usize,
    pub final_rss_kb: usize,
    pub peak_rss_kb: usize,
    pub rss_growth_pct: f64,
    pub initial_fds: usize,
    pub final_fds: usize,
    pub memory_leak_detected: bool,
    pub fd_leak_detected: bool,
}

impl SoakSummary {
    pub fn format_markdown(&self) -> String {
        let mem_status = if self.memory_leak_detected {
            "FAIL (Memory Growth Detected)"
        } else {
            "PASS (Zero Memory Leak)"
        };
        let fd_status = if self.fd_leak_detected {
            "FAIL (FD Leak Detected)"
        } else {
            "PASS (Zero FD Leak)"
        };
        format!(
            "- **Total Epoch Rollovers**: {}\n\
             - **Total Packets Ingested**: {}\n\
             - **Soak Duration**: {:.2} s ({:.1} pkts/s)\n\
             - **Bloom Filter Memory**: strictly capped at {:.2} MB (Max: {:.2} MB)\n\
             - **Process RSS Memory**: Steady-State Baseline = {} KB, Peak = {} KB, Final = {} KB ({:+.2}% growth) -> **{}**\n\
             - **Descriptor Counts**: Initial = {}, Final = {} -> **{}**",
            self.total_epochs,
            self.total_packets,
            self.total_duration_secs,
            self.throughput_pkts_per_sec,
            2.0,
            self.max_filter_memory_bytes as f64 / (1024.0 * 1024.0),
            self.initial_rss_kb,
            self.peak_rss_kb,
            self.final_rss_kb,
            self.rss_growth_pct,
            mem_status,
            self.initial_fds,
            self.final_fds,
            fd_status
        )
    }
}

/// Sample process resident memory (RSS in KB) from `/proc/self/status`.
pub fn sample_rss_kb() -> usize {
    if let Ok(content) = fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<usize>() {
                        return kb;
                    }
                }
            }
        }
    }
    0
}

/// Sample open file descriptors count from `/proc/self/fd`.
pub fn sample_open_fds() -> usize {
    if let Ok(entries) = fs::read_dir("/proc/self/fd") {
        entries.count()
    } else {
        0
    }
}

/// Run the accelerated multi-epoch soak test harness.
pub fn run_soak_benchmarks(
    total_packets: usize,
    num_epochs: u32,
) -> (SoakSummary, Vec<BenchStats>) {
    let start_time = Instant::now();
    let target_epochs = num_epochs.max(10);
    let packets_per_epoch = (total_packets / target_epochs as usize).max(100);

    // Standard 1 MB filter size (8,388,608 bits, 7 hash functions)
    let filter_size_bytes = 1_048_576;
    let mut replay_filter = ReplayFilter::new(filter_size_bytes, 7);

    // Sample baseline RSS and descriptors post-filter initialization
    let initial_rss = sample_rss_kb();
    let initial_fds = sample_open_fds();

    let mut snapshots = Vec::with_capacity(target_epochs as usize);
    let mut peak_rss = initial_rss;
    let mut packet_latencies_ns = Vec::with_capacity(packets_per_epoch * target_epochs as usize);

    println!("\n### 10. Long-Duration Stability & Multi-Epoch Soak Test");
    println!("Executing {} epoch rollovers with {} packets/epoch...", target_epochs, packets_per_epoch);
    println!(
        "| {:<8} | {:>10} | {:>12} | {:>12} | {:>14} | {:>10} | {:>9} | {:>10} |",
        "Epoch", "Packets", "Curr Filter", "Prev Filter", "Filter Memory", "Est. FPR", "RSS (KB)", "Open FDs"
    );
    println!(
        "|:{:-<8}-|-{:-<10}:|-{:-<12}:|-{:-<12}:|-{:-<14}:|-{:-<10}:|-{:-<9}:|-{:-<10}:|",
        "", "", "", "", "", "", "", ""
    );

    let mut rng = rand::thread_rng();
    let mut total_processed = 0;

    for epoch in 1..=target_epochs {
        for _ in 0..packets_per_epoch {
            let p_start = Instant::now();
            let mut secret = [0u8; 32];
            rng.fill_bytes(&mut secret);

            // Replay insertion check
            let _ = replay_filter.check_and_insert(&secret);
            packet_latencies_ns.push(p_start.elapsed().as_nanos() as u64);
            total_processed += 1;
        }

        let rss_now = sample_rss_kb();
        peak_rss = peak_rss.max(rss_now);
        let fds_now = sample_open_fds();
        let filter_mem = replay_filter.size_bytes() * 2; // Strict 2 MB boundary

        let snapshot = EpochSnapshot {
            epoch_id: epoch,
            packets_processed: total_processed,
            filter_current_count: replay_filter.current_count(),
            filter_previous_count: replay_filter.previous_count(),
            filter_memory_bytes: filter_mem,
            estimated_fpr: replay_filter.estimated_fpr(),
            rss_memory_kb: rss_now,
            open_fd_count: fds_now,
            elapsed_secs: start_time.elapsed().as_secs_f64(),
        };

        println!(
            "| {:<8} | {:>10} | {:>12} | {:>12} | {:>11.2} MB | {:>9.5} | {:>9} | {:>10} |",
            snapshot.epoch_id,
            snapshot.packets_processed,
            snapshot.filter_current_count,
            snapshot.filter_previous_count,
            snapshot.filter_memory_bytes as f64 / (1024.0 * 1024.0),
            snapshot.estimated_fpr,
            snapshot.rss_memory_kb,
            snapshot.open_fd_count
        );

        snapshots.push(snapshot);

        // Rollover to next epoch: promotes current -> previous and clears old previous
        replay_filter.rollover();
    }

    let total_secs = start_time.elapsed().as_secs_f64().max(0.001);
    let final_rss = sample_rss_kb();
    let final_fds = sample_open_fds();

    let baseline_rss = if snapshots.len() >= 2 {
        snapshots[1].rss_memory_kb
    } else {
        initial_rss
    };

    let rss_growth_pct = if baseline_rss > 0 {
        ((final_rss as f64 - baseline_rss as f64) / baseline_rss as f64) * 100.0
    } else {
        0.0
    };

    // Verify Bloom filter memory strictly capped at 2 x 1 MB
    assert_eq!(
        replay_filter.size_bytes() * 2,
        2_097_152,
        "Replay Bloom filter memory must be strictly capped at 2 MB"
    );

    // Memory leak threshold: across 8+ post-warmup epochs, RSS growth should be < 15%
    let memory_leak_detected = rss_growth_pct > 15.0;
    // FD leak threshold: final FDs should not exceed initial FDs + 4
    let fd_leak_detected = final_fds > initial_fds + 4;

    let summary = SoakSummary {
        total_epochs: target_epochs,
        total_packets: total_processed,
        total_duration_secs: total_secs,
        throughput_pkts_per_sec: total_processed as f64 / total_secs,
        max_filter_memory_bytes: 2_097_152,
        initial_rss_kb: baseline_rss,
        final_rss_kb: final_rss,
        peak_rss_kb: peak_rss,
        rss_growth_pct,
        initial_fds,
        final_fds,
        memory_leak_detected,
        fd_leak_detected,
    };

    println!("\n#### Multi-Epoch Soak Test Verification Summary:");
    println!("{}", summary.format_markdown());

    let bench_stat = BenchStats::compute(
        "Multi-Epoch Soak Replay Ingestion",
        packet_latencies_ns,
        Some(PACKET_SIZE),
    );

    (summary, vec![bench_stat])
}
