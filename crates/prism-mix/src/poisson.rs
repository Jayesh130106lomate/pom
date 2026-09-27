use rand_distr::{Distribution, Exp};
use std::time::Duration;

pub struct PoissonDelay {
    mu: f64,
    dist: Exp<f64>,
}

impl PoissonDelay {
    pub fn new(mu: f64) -> Self {
        assert!(mu > 0.0, "mu must be greater than 0");
        Self {
            mu,
            dist: Exp::new(mu).unwrap(),
        }
    }

    pub fn sample(&self) -> Duration {
        let mut rng = rand::thread_rng();
        let val = self.dist.sample(&mut rng);
        Duration::from_secs_f64(val)
    }

    pub fn mean_delay(&self) -> Duration {
        Duration::from_secs_f64(1.0 / self.mu)
    }

    /// Sample an adaptive delay scaling with current pool depth.
    pub fn sample_adaptive(&self, pool_depth: usize, target_anonymity_set: usize, max_mu: f64) -> Duration {
        if pool_depth <= target_anonymity_set {
            self.sample()
        } else {
            let ratio = (pool_depth - target_anonymity_set) as f64 / target_anonymity_set.max(1) as f64;
            let eff_mu = (self.mu * (1.0 + ratio)).min(max_mu.max(self.mu));
            let dist = Exp::new(eff_mu).unwrap();
            let mut rng = rand::thread_rng();
            Duration::from_secs_f64(dist.sample(&mut rng))
        }
    }
}

/// Adaptive Poisson delay generator that dynamically scales mixing rate with traffic/pool depth.
///
/// Under low traffic (pool depth <= target_anonymity_set):
///   Uses base_mu (longer delay, high protection, prevents timing correlation).
/// Under high traffic (pool depth > target_anonymity_set):
///   The concurrent packet volume already provides the required anonymity set.
///   The mixing rate scales up proportionally to traffic load, reducing unnecessary latency
///   while strictly maintaining the target anonymity set and minimum reordering entropy.
#[derive(Debug, Clone)]
pub struct AdaptivePoissonDelay {
    base_mu: f64,
    max_mu: f64,
    target_anonymity_set: usize,
    scaling_factor: f64,
    smoothing_alpha: f64,
    smoothed_depth: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl AdaptivePoissonDelay {
    pub fn new(base_mu: f64, max_mu: f64, target_anonymity_set: usize) -> Self {
        assert!(base_mu > 0.0, "base_mu must be > 0");
        assert!(max_mu >= base_mu, "max_mu must be >= base_mu");
        Self {
            base_mu,
            max_mu,
            target_anonymity_set: target_anonymity_set.max(1),
            scaling_factor: 1.0,
            smoothing_alpha: 0.25,
            smoothed_depth: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0.0f64.to_bits())),
        }
    }

    pub fn with_scaling(base_mu: f64, max_mu: f64, target_anonymity_set: usize, scaling_factor: f64) -> Self {
        assert!(base_mu > 0.0, "base_mu must be > 0");
        assert!(max_mu >= base_mu, "max_mu must be >= base_mu");
        Self {
            base_mu,
            max_mu,
            target_anonymity_set: target_anonymity_set.max(1),
            scaling_factor: scaling_factor.max(0.1),
            smoothing_alpha: 0.25,
            smoothed_depth: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0.0f64.to_bits())),
        }
    }

    pub fn with_smoothing(
        base_mu: f64,
        max_mu: f64,
        target_anonymity_set: usize,
        scaling_factor: f64,
        smoothing_alpha: f64,
    ) -> Self {
        assert!(base_mu > 0.0, "base_mu must be > 0");
        assert!(max_mu >= base_mu, "max_mu must be >= base_mu");
        Self {
            base_mu,
            max_mu,
            target_anonymity_set: target_anonymity_set.max(1),
            scaling_factor: scaling_factor.max(0.1),
            smoothing_alpha: smoothing_alpha.clamp(0.01, 1.0),
            smoothed_depth: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0.0f64.to_bits())),
        }
    }

    /// Compute the effective mixing rate mu for a given pool depth or traffic volume.
    pub fn effective_mu(&self, current_pool_depth: usize) -> f64 {
        self.effective_mu_f64(current_pool_depth as f64)
    }

    /// Compute the effective mixing rate mu for a floating-point smoothed depth.
    pub fn effective_mu_f64(&self, depth: f64) -> f64 {
        if depth <= self.target_anonymity_set as f64 {
            self.base_mu
        } else {
            let excess = depth - self.target_anonymity_set as f64;
            let ratio = excess / self.target_anonymity_set as f64;
            let scaled_mu = self.base_mu * (1.0 + self.scaling_factor * ratio);
            scaled_mu.min(self.max_mu)
        }
    }

    /// Sample an adaptive delay for the given current pool depth.
    pub fn sample_for_pool(&self, current_pool_depth: usize) -> Duration {
        let mu = self.effective_mu(current_pool_depth);
        let dist = Exp::new(mu).unwrap();
        let mut rng = rand::thread_rng();
        let val = dist.sample(&mut rng);
        Duration::from_secs_f64(val)
    }

    /// Sample an adaptive delay with exponential moving average (EMA) smoothing.
    /// This smooths rate transitions to prevent step-function timing signatures
    /// and defeats adversarial flow watermarking during traffic transitions.
    pub fn sample_smoothed(&self, current_pool_depth: usize) -> Duration {
        use std::sync::atomic::Ordering;
        let mut old_bits = self.smoothed_depth.load(Ordering::Relaxed);
        let mut new_depth;
        loop {
            let prev = f64::from_bits(old_bits);
            new_depth = if prev == 0.0 && current_pool_depth > 0 {
                current_pool_depth as f64
            } else {
                self.smoothing_alpha * (current_pool_depth as f64) + (1.0 - self.smoothing_alpha) * prev
            };
            match self.smoothed_depth.compare_exchange_weak(
                old_bits,
                new_depth.to_bits(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(b) => old_bits = b,
            }
        }

        let mu = self.effective_mu_f64(new_depth);
        let dist = Exp::new(mu).unwrap();
        let mut rng = rand::thread_rng();
        Duration::from_secs_f64(dist.sample(&mut rng))
    }

    /// Base mean delay (at zero/low traffic).
    pub fn base_mean_delay(&self) -> Duration {
        Duration::from_secs_f64(1.0 / self.base_mu)
    }

    /// Minimum mean delay (at saturated high traffic).
    pub fn min_mean_delay(&self) -> Duration {
        Duration::from_secs_f64(1.0 / self.max_mu)
    }

    pub fn target_anonymity_set(&self) -> usize {
        self.target_anonymity_set
    }

    pub fn base_mu(&self) -> f64 {
        self.base_mu
    }

    pub fn max_mu(&self) -> f64 {
        self.max_mu
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mean_delay() {
        let mu = 5.0;
        let poisson = PoissonDelay::new(mu);
        
        let mut sum = 0.0;
        let count = 10_000;
        
        for _ in 0..count {
            let sample = poisson.sample().as_secs_f64();
            assert!(sample >= 0.0);
            sum += sample;
        }
        
        let mean = sum / (count as f64);
        let expected_mean = 1.0 / mu;
        
        // within 10%
        assert!((mean - expected_mean).abs() < expected_mean * 0.1);
    }

    #[test]
    fn test_cdf() {
        let mu = 2.0;
        let poisson = PoissonDelay::new(mu);
        
        let count = 10_000;
        let mut samples = Vec::with_capacity(count);
        for _ in 0..count {
            samples.push(poisson.sample().as_secs_f64());
        }
        
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        
        // Check 50th percentile (median) for Exp is ln(2)/lambda
        let median = samples[count / 2];
        let expected_median = 2_f64.ln() / mu;
        
        assert!((median - expected_median).abs() < expected_median * 0.15);
    }

    #[test]
    fn test_adaptive_poisson_scaling() {
        let base_mu = 10.0; // 100ms
        let max_mu = 100.0; // 10ms
        let target_anon = 10;
        let adaptive = AdaptivePoissonDelay::new(base_mu, max_mu, target_anon);

        // At or below target pool depth, effective mu equals base_mu
        assert_eq!(adaptive.effective_mu(0), base_mu);
        assert_eq!(adaptive.effective_mu(5), base_mu);
        assert_eq!(adaptive.effective_mu(10), base_mu);

        // At depth = 20 (excess = 10, ratio = 1.0), effective mu should be base_mu * (1 + 1.0) = 20.0
        assert_eq!(adaptive.effective_mu(20), 20.0);

        // At depth = 100 (excess = 90, ratio = 9.0), effective mu = 10 * 10 = 100.0 (capped at max_mu)
        assert_eq!(adaptive.effective_mu(100), 100.0);

        // Beyond cap, remains max_mu
        assert_eq!(adaptive.effective_mu(500), 100.0);
    }

    #[test]
    fn test_adaptive_sampling_decreases_delay() {
        let base_mu = 10.0;
        let max_mu = 100.0;
        let target_anon = 5;
        let adaptive = AdaptivePoissonDelay::new(base_mu, max_mu, target_anon);

        let mut low_sum = 0.0;
        let mut high_sum = 0.0;
        let count = 5000;

        for _ in 0..count {
            low_sum += adaptive.sample_for_pool(3).as_secs_f64();
            high_sum += adaptive.sample_for_pool(50).as_secs_f64();
        }

        let low_mean = low_sum / count as f64;
        let high_mean = high_sum / count as f64;

        // High load delay should be significantly lower than low load delay
        assert!(high_mean < low_mean * 0.3);
        assert!((low_mean - 0.10).abs() < 0.02); // ~100ms
        assert!((high_mean - 0.01).abs() < 0.005); // ~10ms
    }

    #[test]
    fn test_smoothed_adaptive_rate_transitions() {
        let base_mu = 10.0;
        let max_mu = 100.0;
        let target_anon = 10;
        let adaptive = AdaptivePoissonDelay::with_smoothing(base_mu, max_mu, target_anon, 1.0, 0.2);

        // Low traffic
        for _ in 0..10 {
            let _ = adaptive.sample_smoothed(5);
        }

        // An abrupt surge of 100 packets arrives:
        // First sample should NOT jump straight to max_mu (100.0)
        let _ = adaptive.sample_smoothed(100);
        let current_smoothed_depth = f64::from_bits(adaptive.smoothed_depth.load(std::sync::atomic::Ordering::Relaxed));
        // With alpha=0.2, depth rises gradually, dampening step-function timing signatures
        assert!(current_smoothed_depth < 60.0);
    }
}
