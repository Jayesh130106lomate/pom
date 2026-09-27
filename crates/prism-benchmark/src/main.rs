mod stats;
mod bench_crypto;
mod bench_sphinx;
mod bench_mix;
mod bench_directory;
mod bench_transport;
mod bench_e2e;
mod bench_stress;
mod bench_compare;
mod sim_anonymity;
mod bench_load;
mod sim_wan;
mod bench_soak;
mod bench_scalability;

use clap::Parser;
use std::time::Instant;
use stats::BenchStats;

#[derive(Parser, Debug)]
#[command(name = "prism-benchmark", about = "PRISM Mixnet Comprehensive Benchmark & Stress Suite")]
struct Cli {
    /// Benchmark suite to run: crypto, sphinx, mix, directory, transport, e2e, stress, compare, anonymity, load, wan, soak, scale, or all
    #[arg(short, long, default_value = "all")]
    suite: String,

    /// Number of iterations per benchmark
    #[arg(short, long, default_value = "200")]
    iterations: usize,

    /// Duration in seconds for time-bounded benchmarks
    #[arg(long)]
    duration: Option<u64>,

    /// Duration in seconds for soak testing
    #[arg(long)]
    soak_duration: Option<u64>,

    /// Output results as JSON
    #[arg(long)]
    json: bool,

    /// Output detailed markdown tables
    #[arg(long, default_value = "true")]
    markdown: bool,
}

fn print_table_header(title: &str) {
    println!("\n### {}", title);
    println!("| {:<36} | {:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10} |", "Benchmark Target", "Iters", "Mean Latency", "Median (p50)", "95th %ile", "Throughput", "Bandwidth");
    println!("|:{:-<36}-|-{:-<8}:|-{:-<12}:|-{:-<12}:|-{:-<12}:|-{:-<10}:|-{:-<10}:|", "", "", "", "", "", "", "");
}

fn print_stats_table(title: &str, stats: &[BenchStats]) {
    print_table_header(title);
    for s in stats {
        println!("{}", s.format_markdown_row());
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let total_start = Instant::now();

    println!("================================================================================");
    println!("                  PRISM PROTOCOL PROTOTYPE BENCHMARK SUITE                     ");
    println!("================================================================================");
    println!("Suite: {} | Target Iterations: {}", cli.suite, cli.iterations);
    println!("Host Architecture: x86_64-unknown-linux-gnu | Profile: Release / Bench\n");

    let mut all_results: Vec<BenchStats> = Vec::new();

    let run_all = cli.suite == "all";

    // 1. Crypto Primitives
    if run_all || cli.suite == "crypto" {
        println!(">>> Running Cryptographic Primitives Benchmark...");
        let crypto_stats = bench_crypto::run_crypto_benchmarks(cli.iterations);
        print_stats_table("1. Cryptographic Primitives Benchmark", &crypto_stats);
        all_results.extend(crypto_stats);
    }

    // 2. Sphinx Packet Processing
    if run_all || cli.suite == "sphinx" {
        println!("\n>>> Running Sphinx Packet Construction & Processing Benchmark...");
        let sphinx_stats = bench_sphinx::run_sphinx_benchmarks(cli.iterations);
        print_stats_table("2. Sphinx Packet Operations Benchmark", &sphinx_stats);
        all_results.extend(sphinx_stats);
    }

    // 3. Poisson Delay & Mix Pool Scheduling
    if run_all || cli.suite == "mix" {
        println!("\n>>> Running Mix Pool & Poisson Delay Benchmark...");
        let mix_stats = bench_mix::run_mix_benchmarks(cli.iterations).await;
        print_stats_table("3. Mix Pool & Scheduler Benchmark", &mix_stats);
        all_results.extend(mix_stats);
    }

    // 4. Directory Path Selection Scaling
    if run_all || cli.suite == "directory" {
        println!("\n>>> Running Directory Path Selection Scaling Benchmark...");
        let dir_stats = bench_directory::run_directory_benchmarks(cli.iterations);
        print_stats_table("4. Directory Path Selection Scaling Benchmark", &dir_stats);
        all_results.extend(dir_stats);
    }

    // 5. End-to-End Transport
    if run_all || cli.suite == "transport" {
        println!("\n>>> Running QUIC Transport Benchmark...");
        let transport_stats = bench_transport::run_transport_benchmarks(cli.iterations).await;
        print_stats_table("5. QUIC Transport Layer Benchmark", &transport_stats);
        all_results.extend(transport_stats);
    }

    // 6. E2E Multi-Hop Mixnet Pipeline
    if run_all || cli.suite == "e2e" {
        println!("\n>>> Running End-to-End Multi-Hop Mixnet Transport Benchmark...");
        let e2e_stats = bench_e2e::run_e2e_benchmarks((cli.iterations / 4).clamp(10, 50)).await;
        print_stats_table("6. End-to-End Multi-Hop Mixnet Pipeline Benchmark", &e2e_stats);
        all_results.extend(e2e_stats);
    }

    // 7. Stress & Failure Scenarios
    if run_all || cli.suite == "stress" {
        println!("\n>>> Running Stress Testing & Resilience Scenarios...");
        let (stress_stats, stress_report) = bench_stress::run_stress_benchmarks(cli.iterations.max(500));
        print_stats_table("7. Stress Testing & Attack Resilience Benchmark", &stress_stats);
        println!("\n#### Stress Test Resilience Summary:");
        println!("- Replay Flood Packets: {} | Replays Detected: {} ({:.2}% defense rate)", cli.iterations.max(500), stress_report.replay_detected, stress_report.replay_rate);
        println!("- Tampered/Corrupt Flood: {} | Rejected: {} ({:.2}% rejection rate)", cli.iterations.max(500), stress_report.tampered_rejected, stress_report.tampered_rate);
        println!("- MixPool Saturation Capacity: {} queued packets (~{} KB memory)", stress_report.pool_saturation_pkts, stress_report.pool_memory_estimate_kb);
        all_results.extend(stress_stats);
    }

    // 8. Head-to-Head Baseline vs Optimized Comparison
    if run_all || cli.suite == "compare" {
        println!("\n>>> Running Baseline vs Optimized Comparative Benchmark...");
        let (comparisons, comp_stats) = bench_compare::run_comparisons(cli.iterations);

        println!("\n### 8. Optimization Impact: Baseline vs. Optimized Head-to-Head");
        println!("| {:<24} | {:<28} | {:>13} | {:>13} | {:>8} | {:>8} | {:>10} | {:>10} |",
            "Category", "Scenario", "Baseline Lat.", "Optimized Lat.", "Speedup", "Reduction", "Base Ops/s", "Opt Ops/s"
        );
        println!("|:{:-<24}-|-{:-<28}:|-{:-<13}:|-{:-<13}:|-{:-<8}:|-{:-<8}:|-{:-<10}:|-{:-<10}:|",
            "", "", "", "", "", "", "", ""
        );
        for c in &comparisons {
            println!("{}", c.format_markdown_row());
        }
        all_results.extend(comp_stats);
    }

    // 9. Anonymity & Traffic Analysis Evaluation
    if run_all || cli.suite == "anonymity" {
        sim_anonymity::run_anonymity_eval(cli.iterations);
    }

    // 10. Multi-Tier Traffic Load & Mixing Efficiency
    if run_all || cli.suite == "load" {
        let (_load_comps, load_stats) = bench_load::run_load_benchmarks();
        all_results.extend(load_stats);
    }

    // 11. WAN Network-Impairment Validation
    if run_all || cli.suite == "wan" {
        let wan_stats = sim_wan::run_wan_benchmarks(cli.iterations.max(100));
        all_results.extend(wan_stats);
    }

    // 12. Long-Duration Stability & Soak Testing
    if run_all || cli.suite == "soak" {
        let target_iters = if let Some(soak_secs) = cli.soak_duration {
            (soak_secs as usize * 1000).max(1000)
        } else {
            cli.iterations.max(1000)
        };
        let (_soak_summary, soak_stats) = bench_soak::run_soak_benchmarks(target_iters, 10);
        all_results.extend(soak_stats);
    }

    // 13. Scalability Testing (10 to 50,000 Users)
    if run_all || cli.suite == "scale" || cli.suite == "scalability" {
        let scale_stats = bench_scalability::run_scalability_benchmarks(50_000);
        all_results.extend(scale_stats);
    }

    let total_elapsed = total_start.elapsed();
    println!("\n================================================================================");
    println!("Benchmark suite completed in {:.2} seconds.", total_elapsed.as_secs_f64());
    println!("================================================================================");

    if cli.json {
        let json_out = serde_json::to_string_pretty(&all_results)?;
        println!("\n--- JSON OUTPUT ---\n{}", json_out);
    }

    Ok(())
}
