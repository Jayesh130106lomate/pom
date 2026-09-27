#[derive(Debug, Default)]
pub struct MixMetrics {
    pub packets_mixed: u64,
    pub average_delay_ms: f64,
    pub pool_size_avg: f64,
    pub cover_packets_sent: u64,
    pub real_packets_sent: u64,
}

impl MixMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_packet(&mut self, delay_ms: f64, is_cover: bool) {
        self.packets_mixed += 1;
        
        // Moving average for delay
        let n = self.packets_mixed as f64;
        self.average_delay_ms = self.average_delay_ms * ((n - 1.0) / n) + (delay_ms / n);
        
        if is_cover {
            self.cover_packets_sent += 1;
        } else {
            self.real_packets_sent += 1;
        }
    }

    pub fn mixing_ratio(&self) -> f64 {
        let total = self.cover_packets_sent + self.real_packets_sent;
        if total == 0 {
            0.0
        } else {
            self.cover_packets_sent as f64 / total as f64
        }
    }

    pub fn report(&self) -> String {
        format!(
            "Mixed: {}, Avg Delay: {:.2}ms, Cover Ratio: {:.2}%",
            self.packets_mixed,
            self.average_delay_ms,
            self.mixing_ratio() * 100.0
        )
    }
}
