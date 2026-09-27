//! PRISM relay node configuration.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Relay node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Listen address for incoming QUIC connections.
    pub listen_addr: SocketAddr,

    /// This relay's layer assignment (1-based).
    pub layer: u8,

    /// Poisson mixing rate parameter (μ).
    /// Mean delay = 1/μ seconds.
    pub mix_rate: f64,

    /// Minimum pool size before releasing packets.
    pub min_pool_size: usize,

    /// Current epoch ID.
    pub epoch_id: u32,

    /// Maximum packet processing rate (packets/sec).
    pub max_packet_rate: u64,

    /// Path to store relay identity keys.
    pub key_path: String,

    /// Whether to enable traffic-aware adaptive mixing.
    #[serde(default)]
    pub adaptive_mixing: bool,

    /// Maximum mixing rate for adaptive mixing.
    #[serde(default)]
    pub max_mix_rate: Option<f64>,

    /// Target anonymity set size before scaling mixing rate.
    #[serde(default)]
    pub target_anonymity_set: Option<usize>,

    /// Maximum batch size for parallel packet unpeeling.
    #[serde(default)]
    pub batch_size: Option<usize>,

    /// Maximum capacity of the MixPool before shedding packets.
    #[serde(default)]
    pub max_pool_capacity: Option<usize>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            listen_addr: "0.0.0.0:9001".parse().unwrap(),
            layer: 1,
            mix_rate: 2.0,       // mean delay = 500ms
            min_pool_size: 5,
            epoch_id: 1,
            max_packet_rate: 3000,
            key_path: "relay_keys.json".into(),
            adaptive_mixing: true,
            max_mix_rate: Some(200.0),
            target_anonymity_set: Some(10),
            batch_size: Some(64),
            max_pool_capacity: Some(10_000),
        }
    }
}
