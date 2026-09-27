use std::time::Instant;
use rand::Rng;
use crate::stats::BenchStats;
use prism_directory::{
    directory::NetworkDirectory,
    epoch::{EpochInfo, MixParameters},
    path_select::select_path,
    relay_info::RelayInfo,
};

pub fn generate_synthetic_directory(num_relays: usize, num_layers: u8) -> NetworkDirectory {
    let mut rng = rand::thread_rng();
    let mut relays = Vec::with_capacity(num_relays);

    let country_codes = ["US", "DE", "FR", "GB", "NL", "JP", "SG", "CH", "SE", "CA", "AU", "BR"];

    for i in 0..num_relays {
        let layer = ((i % num_layers as usize) + 1) as u8;
        let asn = (1000 + (i % 50)) as u32;
        let cc = country_codes[i % country_codes.len()].to_string();
        let mut id = [0u8; 32];
        id[0..8].copy_from_slice(&(i as u64).to_be_bytes());

        relays.push(RelayInfo {
            id,
            identity_key: vec![0x11; 32],
            sphinx_public_key: vec![0x22; 32],
            address: format!("10.0.{}.{}:9001", (i / 250) % 250, i % 250).parse().unwrap(),
            layer,
            bandwidth_capacity: 10_000_000 + rng.gen_range(0..50_000_000),
            autonomous_system: asn,
            country_code: cc,
            uptime_hours: 500,
            stake_amount: 10_000,
        });
    }

    NetworkDirectory {
        epoch: EpochInfo {
            epoch_id: 1,
            start_time: 1000000,
            duration_secs: 3600,
            relays,
            mix_parameters: MixParameters {
                mu: 5.0,
                cover_rate: 1.0,
                packet_size: 32768,
                max_hops: 5,
                min_pool_size: 10,
            },
        },
        signature: vec![0x33; 64],
    }
}

pub fn run_directory_benchmarks(iters: usize) -> Vec<BenchStats> {
    let mut results = Vec::new();
    let mut rng = rand::thread_rng();

    // 1. Path Selection Scaling by Directory Size (3 hops)
    for size in [30, 100, 500, 1000, 5000] {
        let dir = generate_synthetic_directory(size, 3);
        let mut samples = Vec::with_capacity(iters);
        for _ in 0..iters {
            let start = Instant::now();
            let _ = select_path(&dir, 3, &mut rng).unwrap();
            samples.push(start.elapsed().as_nanos() as u64);
        }
        results.push(BenchStats::compute(
            &format!("Path Select (3 hops, N={} relays)", size),
            samples,
            None,
        ));
    }

    // 2. Path Selection Scaling by Hop Count (N=1000 relays, 5 layers)
    let dir_5l = generate_synthetic_directory(1000, 5);
    for hops in [1, 2, 3, 5] {
        let mut samples = Vec::with_capacity(iters);
        for _ in 0..iters {
            let start = Instant::now();
            let _ = select_path(&dir_5l, hops, &mut rng).unwrap();
            samples.push(start.elapsed().as_nanos() as u64);
        }
        results.push(BenchStats::compute(
            &format!("Path Select ({} hops, N=1000 relays)", hops),
            samples,
            None,
        ));
    }

    // 3. Constraint Verification & Success Rate
    let dir_dense = generate_synthetic_directory(500, 3);
    let mut strict_count = 0;
    let check_iters = (iters * 2).max(200);
    for _ in 0..check_iters {
        if let Ok(path) = select_path(&dir_dense, 3, &mut rng) {
            let asns: std::collections::HashSet<_> = path.iter().map(|r| r.autonomous_system).collect();
            let ccs: std::collections::HashSet<_> = path.iter().map(|r| &r.country_code).collect();
            if asns.len() == 3 && ccs.len() == 3 {
                strict_count += 1;
            }
        }
    }
    let strict_rate = (strict_count as f64 / check_iters as f64) * 100.0;
    println!(
        "Directory diversity constraints check: {:.1}% paths satisfied strict ASN & Country diversity ({} runs)",
        strict_rate, check_iters
    );

    results
}
