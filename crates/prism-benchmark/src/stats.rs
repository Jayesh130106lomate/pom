use std::time::Duration;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchStats {
    pub name: String,
    pub iterations: usize,
    pub total_time_ms: f64,
    pub mean_us: f64,
    pub median_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
    pub min_us: f64,
    pub max_us: f64,
    pub ops_per_sec: f64,
    pub throughput_mb_s: Option<f64>,
}

impl BenchStats {
    pub fn compute(name: &str, mut samples_ns: Vec<u64>, bytes_per_op: Option<usize>) -> Self {
        let iterations = samples_ns.len();
        if iterations == 0 {
            return Self {
                name: name.to_string(),
                iterations: 0,
                total_time_ms: 0.0,
                mean_us: 0.0,
                median_us: 0.0,
                p95_us: 0.0,
                p99_us: 0.0,
                min_us: 0.0,
                max_us: 0.0,
                ops_per_sec: 0.0,
                throughput_mb_s: None,
            };
        }

        samples_ns.sort_unstable();

        let total_ns: u64 = samples_ns.iter().sum();
        let total_time_ms = total_ns as f64 / 1_000_000.0;
        let mean_us = (total_ns as f64 / iterations as f64) / 1_000.0;

        let median_us = samples_ns[iterations / 2] as f64 / 1_000.0;
        let p95_idx = ((iterations as f64 * 0.95).round() as usize).min(iterations - 1);
        let p95_us = samples_ns[p95_idx] as f64 / 1_000.0;
        let p99_idx = ((iterations as f64 * 0.99).round() as usize).min(iterations - 1);
        let p99_us = samples_ns[p99_idx] as f64 / 1_000.0;

        let min_us = samples_ns[0] as f64 / 1_000.0;
        let max_us = samples_ns[iterations - 1] as f64 / 1_000.0;

        let total_secs = total_ns as f64 / 1_000_000_000.0;
        let ops_per_sec = if total_secs > 0.0 {
            iterations as f64 / total_secs
        } else {
            0.0
        };

        let throughput_mb_s = bytes_per_op.map(|bytes| {
            let total_bytes = bytes as f64 * iterations as f64;
            (total_bytes / (1024.0 * 1024.0)) / total_secs
        });

        Self {
            name: name.to_string(),
            iterations,
            total_time_ms,
            mean_us,
            median_us,
            p95_us,
            p99_us,
            min_us,
            max_us,
            ops_per_sec,
            throughput_mb_s,
        }
    }

    pub fn format_markdown_row(&self) -> String {
        let tp_str = match self.throughput_mb_s {
            Some(mb) => format!("{:.2} MB/s", mb),
            None => "-".to_string(),
        };
        format!(
            "| {:<36} | {:>8} | {:>9.2} µs | {:>9.2} µs | {:>9.2} µs | {:>10.1} | {:>10} |",
            self.name, self.iterations, self.mean_us, self.median_us, self.p95_us, self.ops_per_sec, tp_str
        )
    }
}

#[allow(dead_code)]
pub fn time_operation<F: FnMut()>(mut f: F) -> Duration {
    let start = std::time::Instant::now();
    f();
    start.elapsed()
}

#[allow(dead_code)]
pub async fn time_async_operation<F, Fut>(f: F) -> Duration
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let start = std::time::Instant::now();
    f().await;
    start.elapsed()
}
