//! Relay node state management.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Runtime state of the relay node.
pub struct NodeState {
    /// Total packets received.
    pub packets_received: AtomicU64,
    /// Total packets forwarded.
    pub packets_forwarded: AtomicU64,
    /// Total packets dropped (cover traffic).
    pub packets_dropped: AtomicU64,
    /// Total packets delivered at destination (exit node).
    pub packets_delivered: AtomicU64,
    /// Total replays detected.
    pub replays_detected: AtomicU64,
    /// Total MAC failures.
    pub mac_failures: AtomicU64,
    /// Total packets dropped by ingress rate limiting.
    pub packets_dropped_rate_limit: AtomicU64,
    /// Total packets dropped due to transport backpressure.
    pub packets_dropped_backpressure: AtomicU64,
    /// Total packets dropped due to MixPool capacity overflow.
    pub pool_overflow_drops: AtomicU64,
    /// Total incoming connections rejected by admission control.
    pub connections_rejected: AtomicU64,
    /// Currently active QUIC connections.
    pub active_connections: AtomicUsize,
    /// Current MixPool queued items.
    pub mix_pool_depth: AtomicUsize,
    /// Highest observed MixPool depth.
    pub mix_pool_high_water: AtomicUsize,
    /// Items currently tracked in Bloom replay filter.
    pub replay_filter_count: AtomicUsize,
    /// Bloom replay filter estimated FPR in parts per million (e.g. 15 = 0.000015).
    pub replay_filter_fpr_ppm: AtomicU64,
}

impl NodeState {
    pub fn new() -> Self {
        NodeState {
            packets_received: AtomicU64::new(0),
            packets_forwarded: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_delivered: AtomicU64::new(0),
            replays_detected: AtomicU64::new(0),
            mac_failures: AtomicU64::new(0),
            packets_dropped_rate_limit: AtomicU64::new(0),
            packets_dropped_backpressure: AtomicU64::new(0),
            pool_overflow_drops: AtomicU64::new(0),
            connections_rejected: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            mix_pool_depth: AtomicUsize::new(0),
            mix_pool_high_water: AtomicUsize::new(0),
            replay_filter_count: AtomicUsize::new(0),
            replay_filter_fpr_ppm: AtomicU64::new(0),
        }
    }

    pub fn report(&self) -> String {
        format!(
            "received={} forwarded={} delivered={} dropped={} replays={} mac_failures={} rate_limit_drops={} backpressure_drops={} pool_overflows={} conns_rejected={} active_conns={} pool_depth={} pool_max={} rf_count={}",
            self.packets_received.load(Ordering::Relaxed),
            self.packets_forwarded.load(Ordering::Relaxed),
            self.packets_delivered.load(Ordering::Relaxed),
            self.packets_dropped.load(Ordering::Relaxed),
            self.replays_detected.load(Ordering::Relaxed),
            self.mac_failures.load(Ordering::Relaxed),
            self.packets_dropped_rate_limit.load(Ordering::Relaxed),
            self.packets_dropped_backpressure.load(Ordering::Relaxed),
            self.pool_overflow_drops.load(Ordering::Relaxed),
            self.connections_rejected.load(Ordering::Relaxed),
            self.active_connections.load(Ordering::Relaxed),
            self.mix_pool_depth.load(Ordering::Relaxed),
            self.mix_pool_high_water.load(Ordering::Relaxed),
            self.replay_filter_count.load(Ordering::Relaxed),
        )
    }
}

impl Default for NodeState {
    fn default() -> Self {
        Self::new()
    }
}
