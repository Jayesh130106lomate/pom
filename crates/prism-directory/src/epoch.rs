use crate::relay_info::RelayInfo;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixParameters {
    pub mu: f64,
    pub cover_rate: f64,
    pub packet_size: usize,
    pub max_hops: usize,
    pub min_pool_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochInfo {
    pub epoch_id: u64,
    pub start_time: u64,
    pub duration_secs: u64,
    pub relays: Vec<RelayInfo>,
    pub mix_parameters: MixParameters,
}

pub fn current_epoch(epoch_duration: u64) -> u64 {
    if epoch_duration == 0 {
        return 0;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    now / epoch_duration
}

pub fn epoch_start_time(epoch_id: u64, epoch_duration: u64) -> u64 {
    epoch_id.saturating_mul(epoch_duration)
}

pub fn time_until_next_epoch(epoch_duration: u64) -> Duration {
    if epoch_duration == 0 {
        return Duration::ZERO;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let current = now / epoch_duration;
    let next_start = (current + 1).saturating_mul(epoch_duration);
    Duration::from_secs(next_start.saturating_sub(now))
}
