use std::time::Instant;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use prism_crypto::kdf::hkdf_sha256;
use prism_mix::poisson::{AdaptivePoissonDelay, PoissonDelay};
use prism_sphinx::constants::PACKET_SIZE;
use prism_sphinx::packet::{create_sphinx_packet, process_sphinx_packet};
use prism_sphinx::routing::{PacketFlag, RouteHop, RoutingInfo};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use crate::stats::BenchStats;

#[derive(Debug, Clone)]
pub struct ComparisonResult {
    pub category: String,
    pub scenario: String,
    pub baseline_mean_us: f64,
    pub optimized_mean_us: f64,
    pub speedup_ratio: f64,
    pub latency_reduction_pct: f64,
    pub baseline_ops_per_sec: f64,
    pub optimized_ops_per_sec: f64,
}

impl ComparisonResult {
    pub fn new(category: &str, scenario: &str, base: &BenchStats, opt: &BenchStats) -> Self {
        let speedup_ratio = if opt.mean_us > 0.0 {
            base.mean_us / opt.mean_us
        } else {
            1.0
        };
        let latency_reduction_pct = if base.mean_us > 0.0 {
            ((base.mean_us - opt.mean_us) / base.mean_us) * 100.0
        } else {
            0.0
        };

        Self {
            category: category.to_string(),
            scenario: scenario.to_string(),
            baseline_mean_us: base.mean_us,
            optimized_mean_us: opt.mean_us,
            speedup_ratio,
            latency_reduction_pct,
            baseline_ops_per_sec: base.ops_per_sec,
            optimized_ops_per_sec: opt.ops_per_sec,
        }
    }

    pub fn format_markdown_row(&self) -> String {
        format!(
            "| {:<24} | {:<28} | {:>10.2} µs | {:>10.2} µs | {:>7.1}x | {:>7.1}% | {:>10.0} | {:>10.0} |",
            self.category,
            self.scenario,
            self.baseline_mean_us,
            self.optimized_mean_us,
            self.speedup_ratio,
            self.latency_reduction_pct,
            self.baseline_ops_per_sec,
            self.optimized_ops_per_sec,
        )
    }
}

// -------------------------------------------------------------
// Baseline vs Optimized Implementations
// -------------------------------------------------------------

// A. Stream Cipher: Baseline HKDF loop
fn baseline_hkdf_keystream(key: &[u8; 32], needed: usize) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(needed + 32);
    let mut counter = 0u32;
    while keystream.len() < needed {
        let block = hkdf_sha256(key, b"prism-sphinx-stream", &counter.to_be_bytes(), 32);
        keystream.extend_from_slice(&block);
        counter += 1;
    }
    keystream.truncate(needed);
    keystream
}

fn baseline_stream_cipher(key: &[u8; 32], data: &mut [u8]) {
    let ks = baseline_hkdf_keystream(key, data.len());
    for (d, k) in data.iter_mut().zip(ks.iter()) {
        *d ^= k;
    }
}

// A. Stream Cipher: Optimized ChaCha20
fn optimized_chacha20_stream_cipher(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(data);
}

// B. Bloom Filter: Baseline 7-HKDF Replay Filter
struct BaselineBloomFilter {
    bits: Vec<u8>,
    k: usize,
    m: usize,
}

impl BaselineBloomFilter {
    fn new(size_bytes: usize, k: usize) -> Self {
        Self {
            bits: vec![0u8; size_bytes],
            k,
            m: size_bytes * 8,
        }
    }

    fn hash_positions(&self, tag: &[u8; 32]) -> Vec<usize> {
        let mut positions = Vec::with_capacity(self.k);
        for i in 0..self.k {
            let hash_input = hkdf_sha256(tag, b"prism-bloom", &(i as u32).to_be_bytes(), 8);
            let pos_bytes: [u8; 8] = hash_input[0..8].try_into().unwrap();
            let pos = (u64::from_be_bytes(pos_bytes) as usize) % self.m;
            positions.push(pos);
        }
        positions
    }

    fn check_and_insert(&mut self, tag: &[u8; 32]) -> bool {
        // Baseline computes positions in might_contain AND then again in insert
        let mut was_present = true;
        for pos in self.hash_positions(tag) {
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            if self.bits[byte_idx] & (1 << bit_idx) == 0 {
                was_present = false;
                break;
            }
        }
        for pos in self.hash_positions(tag) {
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            self.bits[byte_idx] |= 1 << bit_idx;
        }
        was_present
    }
}

// B. Bloom Filter: Optimized Kirsch-Mitzenmacher Double-Hashing Replay Filter
struct OptimizedBloomFilter {
    bits: Vec<u8>,
    k: usize,
    m: usize,
}

impl OptimizedBloomFilter {
    fn new(size_bytes: usize, k: usize) -> Self {
        Self {
            bits: vec![0u8; size_bytes],
            k,
            m: size_bytes * 8,
        }
    }

    #[inline(always)]
    fn check_and_insert(&mut self, tag: &[u8; 32]) -> bool {
        // Derive 16 bytes for two 64-bit hashes h1 and h2
        let hash_input = hkdf_sha256(tag, b"prism-bloom-km", b"double-hash", 16);
        let h1 = u64::from_be_bytes(hash_input[0..8].try_into().unwrap());
        let h2 = u64::from_be_bytes(hash_input[8..16].try_into().unwrap()) | 1;

        let mut was_present = true;
        for i in 0..self.k {
            let pos = (h1.wrapping_add((i as u64).wrapping_mul(h2)) as usize) % self.m;
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            let mask = 1 << bit_idx;
            if self.bits[byte_idx] & mask == 0 {
                was_present = false;
            }
            self.bits[byte_idx] |= mask;
        }
        was_present
    }
}

pub fn run_comparisons(iters: usize) -> (Vec<ComparisonResult>, Vec<BenchStats>) {
    let mut comparisons = Vec::new();
    let mut all_stats = Vec::new();

    let key = [0x5Au8; 32];
    let nonce = [0x12u8; 12];

    // =========================================================================
    // Comparison 1: Routing Info Keystream (280 Bytes)
    // =========================================================================
    let ri_len = 280;
    let mut ri_base_samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let mut buf = vec![0x11u8; ri_len];
        let start = Instant::now();
        baseline_stream_cipher(&key, &mut buf);
        ri_base_samples.push(start.elapsed().as_nanos() as u64);
    }
    let ri_base_stat = BenchStats::compute("Baseline HKDF (Routing Info 280B)", ri_base_samples, Some(ri_len));

    let mut ri_opt_samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let mut buf = vec![0x11u8; ri_len];
        let start = Instant::now();
        optimized_chacha20_stream_cipher(&key, &nonce, &mut buf);
        ri_opt_samples.push(start.elapsed().as_nanos() as u64);
    }
    let ri_opt_stat = BenchStats::compute("ChaCha20 (Routing Info 280B)", ri_opt_samples, Some(ri_len));

    comparisons.push(ComparisonResult::new(
        "Stream Cipher",
        "Routing Info (280 Bytes)",
        &ri_base_stat,
        &ri_opt_stat,
    ));
    all_stats.push(ri_base_stat);
    all_stats.push(ri_opt_stat);

    // =========================================================================
    // Comparison 2: Full Payload Encryption (31,744 Bytes)
    // =========================================================================
    let payload_len = 31_744;
    let payload_iters = (iters / 4).max(50);

    let mut pl_base_samples = Vec::with_capacity(payload_iters);
    for _ in 0..payload_iters {
        let mut buf = vec![0x22u8; payload_len];
        let start = Instant::now();
        baseline_stream_cipher(&key, &mut buf);
        pl_base_samples.push(start.elapsed().as_nanos() as u64);
    }
    let pl_base_stat = BenchStats::compute(
        "Baseline HKDF (Payload 31.7KB)",
        pl_base_samples,
        Some(payload_len),
    );

    let mut pl_opt_samples = Vec::with_capacity(payload_iters);
    for _ in 0..payload_iters {
        let mut buf = vec![0x22u8; payload_len];
        let start = Instant::now();
        optimized_chacha20_stream_cipher(&key, &nonce, &mut buf);
        pl_opt_samples.push(start.elapsed().as_nanos() as u64);
    }
    let pl_opt_stat = BenchStats::compute(
        "ChaCha20 (Payload 31.7KB)",
        pl_opt_samples,
        Some(payload_len),
    );

    comparisons.push(ComparisonResult::new(
        "Stream Cipher",
        "Sphinx Payload (31.7 KB)",
        &pl_base_stat,
        &pl_opt_stat,
    ));
    all_stats.push(pl_base_stat);
    all_stats.push(pl_opt_stat);

    // =========================================================================
    // Comparison 3: Bloom Filter Replay Check & Insert
    // =========================================================================
    let bloom_iters = (iters * 2).max(200);
    let mut base_bloom = BaselineBloomFilter::new(1024 * 1024, 7);
    let mut base_bloom_samples = Vec::with_capacity(bloom_iters);
    for i in 0..bloom_iters {
        let mut tag = [0u8; 32];
        tag[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        let start = Instant::now();
        base_bloom.check_and_insert(&tag);
        base_bloom_samples.push(start.elapsed().as_nanos() as u64);
    }
    let base_bloom_stat = BenchStats::compute(
        "Baseline 7-HKDF Bloom Filter",
        base_bloom_samples,
        None,
    );

    let mut opt_bloom = OptimizedBloomFilter::new(1024 * 1024, 7);
    let mut opt_bloom_samples = Vec::with_capacity(bloom_iters);
    for i in 0..bloom_iters {
        let mut tag = [0u8; 32];
        tag[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        let start = Instant::now();
        opt_bloom.check_and_insert(&tag);
        opt_bloom_samples.push(start.elapsed().as_nanos() as u64);
    }
    let opt_bloom_stat = BenchStats::compute(
        "Double-Hashing Bloom Filter",
        opt_bloom_samples,
        None,
    );

    comparisons.push(ComparisonResult::new(
        "Replay Detection",
        "Bloom Check & Insert (k=7)",
        &base_bloom_stat,
        &opt_bloom_stat,
    ));
    all_stats.push(base_bloom_stat);
    all_stats.push(opt_bloom_stat);

    // =========================================================================
    // Comparison 4: Packet Processing In-Place vs Allocation Cloning
    // =========================================================================
    let proc_iters = (iters / 2).max(100);

    // Simulated Relay Processing: Clone vs In-place
    let mut clone_samples = Vec::with_capacity(proc_iters);
    for _ in 0..proc_iters {
        let incoming_payload = vec![0x33u8; payload_len];
        let start = Instant::now();
        // Baseline: clone buffer, then apply stream cipher
        let mut cloned = incoming_payload.clone();
        optimized_chacha20_stream_cipher(&key, &nonce, &mut cloned);
        let _ = cloned;
        clone_samples.push(start.elapsed().as_nanos() as u64);
    }
    let clone_stat = BenchStats::compute(
        "Packet Processing (Cloning 32KB)",
        clone_samples,
        Some(payload_len),
    );

    let mut inplace_samples = Vec::with_capacity(proc_iters);
    for _ in 0..proc_iters {
        let mut incoming_payload = vec![0x33u8; payload_len];
        let start = Instant::now();
        // Optimized: mutate in place, zero clones
        optimized_chacha20_stream_cipher(&key, &nonce, &mut incoming_payload);
        inplace_samples.push(start.elapsed().as_nanos() as u64);
    }
    let inplace_stat = BenchStats::compute(
        "Packet Processing (In-Place Mutate)",
        inplace_samples,
        Some(payload_len),
    );

    comparisons.push(ComparisonResult::new(
        "Memory & Buffer Mgmt",
        "Packet Processing (In-Place)",
        &clone_stat,
        &inplace_stat,
    ));
    all_stats.push(clone_stat);
    all_stats.push(inplace_stat);

    // =========================================================================
    // Comparison 5: Ingress Crypto Unpeeling (Sequential 1-Core vs Parallel 6-Core)
    // =========================================================================
    let sk = X25519Secret::random_from_rng(rand::thread_rng());
    let pk = X25519Public::from(&sk);
    let hop = RouteHop {
        routing: RoutingInfo {
            next_hop: "127.0.0.1:9001".parse().unwrap(),
            delay_seed: 0,
            flag: PacketFlag::FinalHop,
            reserved: 0,
        },
        public_key: pk.to_bytes(),
    };
    let test_pkt = create_sphinx_packet(b"bench compare packet unpeel payload", &[hop], 1).unwrap();
    let test_bytes = test_pkt.to_bytes();
    let relay_sk = sk.to_bytes();

    let batch_size = 16;
    let unpeel_iters = (iters / 4).clamp(10, 50);

    // Sequential 1-Core baseline
    let mut seq_samples = Vec::with_capacity(unpeel_iters);
    for _ in 0..unpeel_iters {
        let start = Instant::now();
        for _ in 0..batch_size {
            let pkt = prism_sphinx::packet::SphinxPacket::from_bytes(&test_bytes).unwrap();
            let _ = process_sphinx_packet(&pkt, &relay_sk).unwrap();
        }
        seq_samples.push(start.elapsed().as_nanos() as u64);
    }
    let seq_stat = BenchStats::compute(
        &format!("Sequential Ingestion ({} pkts)", batch_size),
        seq_samples,
        Some(PACKET_SIZE * batch_size),
    );

    // Parallel multi-core optimized (Rayon work-stealing pool)
    use rayon::prelude::*;
    let test_batch: Vec<Vec<u8>> = (0..batch_size).map(|_| test_bytes.clone()).collect();
    let mut par_samples = Vec::with_capacity(unpeel_iters);
    for _ in 0..unpeel_iters {
        let b = test_batch.clone();
        let start = Instant::now();
        let _res: Vec<_> = b
            .into_par_iter()
            .map(|raw| {
                let pkt = prism_sphinx::packet::SphinxPacket::from_bytes(&raw).unwrap();
                prism_sphinx::packet::process_sphinx_packet_in_place(pkt, &relay_sk).unwrap()
            })
            .collect();
        par_samples.push(start.elapsed().as_nanos() as u64);
    }
    let par_stat = BenchStats::compute(
        &format!("Parallel Batched Ingestion ({} pkts)", batch_size),
        par_samples,
        Some(PACKET_SIZE * batch_size),
    );

    comparisons.push(ComparisonResult::new(
        "Parallel Processing",
        &format!("Relay Ingestion ({} pkts)", batch_size),
        &seq_stat,
        &par_stat,
    ));
    all_stats.push(seq_stat);
    all_stats.push(par_stat);

    // =========================================================================
    // Comparison 6: Mixing Delay at High Traffic (Static 100ms vs Adaptive Mixing)
    // =========================================================================
    let high_load_iters = (iters * 2).max(100);
    let base_poisson = PoissonDelay::new(10.0); // 100ms
    let opt_adaptive = AdaptivePoissonDelay::new(10.0, 150.0, 10);

    let mut base_mix_samples = Vec::with_capacity(high_load_iters);
    for _ in 0..high_load_iters {
        let d = base_poisson.sample();
        base_mix_samples.push(d.as_nanos() as u64);
    }
    let base_mix_stat = BenchStats::compute(
        "Static Mixing Delay (mu=10)",
        base_mix_samples,
        None,
    );

    let mut opt_mix_samples = Vec::with_capacity(high_load_iters);
    for _ in 0..high_load_iters {
        let d = opt_adaptive.sample_for_pool(50); // pool depth = 50 under high traffic
        opt_mix_samples.push(d.as_nanos() as u64);
    }
    let opt_mix_stat = BenchStats::compute(
        "Adaptive Mixing Delay (N=50)",
        opt_mix_samples,
        None,
    );

    comparisons.push(ComparisonResult::new(
        "Adaptive Mixing",
        "High Load Mixing Delay (N=50)",
        &base_mix_stat,
        &opt_mix_stat,
    ));
    all_stats.push(base_mix_stat);
    all_stats.push(opt_mix_stat);

    (comparisons, all_stats)
}
