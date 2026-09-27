use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    pub id: [u8; 32],                    // Unique relay ID (hash of identity key)
    pub identity_key: Vec<u8>,           // Ed25519 public key
    pub sphinx_public_key: Vec<u8>,      // Hybrid KEM public key for this epoch
    pub address: SocketAddr,             // IP:port
    pub layer: u8,                       // Which layer (1, 2, 3, etc.)
    pub bandwidth_capacity: u64,         // Advertised capacity in bytes/sec
    pub autonomous_system: u32,          // AS number
    pub country_code: String,            // ISO 3166-1 alpha-2
    pub uptime_hours: u64,               // Total uptime
    pub stake_amount: u64,               // Staked tokens
}
