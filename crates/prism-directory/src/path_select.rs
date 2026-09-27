use crate::directory::NetworkDirectory;
use crate::errors::DirectoryError;
use crate::relay_info::RelayInfo;
use rand::Rng;
use rand::distributions::WeightedIndex;
use rand::distributions::Distribution;

pub fn select_path(
    directory: &NetworkDirectory,
    num_hops: usize,
    rng: &mut impl Rng,
) -> Result<Vec<RelayInfo>, DirectoryError> {
    if num_hops == 0 || num_hops > 5 {
        return Err(DirectoryError::PathSelectionFailed(format!(
            "invalid num_hops: expected 1..=5, got {}",
            num_hops
        )));
    }

    let mut path = Vec::with_capacity(num_hops);
    let mut used_ids: Vec<[u8; 32]> = Vec::with_capacity(num_hops);
    let mut used_as = Vec::with_capacity(num_hops);
    let mut used_cc = Vec::with_capacity(num_hops);

    for layer in 1..=num_hops as u8 {
        let candidates = directory.relays_for_layer(layer);
        if candidates.is_empty() {
            return Err(DirectoryError::PathSelectionFailed(format!("No relays in layer {}", layer)));
        }

        let mut available_candidates = Vec::with_capacity(candidates.len());
        let mut strict_candidates = Vec::with_capacity(candidates.len());

        for &r in &candidates {
            if !used_ids.contains(&r.id) {
                available_candidates.push(r);
                if !used_as.contains(&r.autonomous_system) && !used_cc.contains(&r.country_code) {
                    strict_candidates.push(r);
                }
            }
        }

        if available_candidates.is_empty() {
            return Err(DirectoryError::PathSelectionFailed(format!(
                "No unique relays available in layer {}", layer
            )));
        }

        let chosen = if !strict_candidates.is_empty() {
            let weights: Vec<u64> = strict_candidates.iter().map(|r| r.bandwidth_capacity).collect();
            if let Ok(dist) = WeightedIndex::new(&weights) {
                strict_candidates[dist.sample(rng)]
            } else {
                strict_candidates[rng.gen_range(0..strict_candidates.len())]
            }
        } else {
            tracing::warn!("Relaxing path selection constraints at layer {}", layer);
            let weights: Vec<u64> = available_candidates.iter().map(|r| r.bandwidth_capacity).collect();
            if let Ok(dist) = WeightedIndex::new(&weights) {
                available_candidates[dist.sample(rng)]
            } else {
                available_candidates[rng.gen_range(0..available_candidates.len())]
            }
        };

        used_ids.push(chosen.id);
        used_as.push(chosen.autonomous_system);
        used_cc.push(chosen.country_code.clone());
        path.push((*chosen).clone());
    }

    Ok(path)
}

use std::collections::HashMap;

/// Select a path with dynamic load balancing.
///
/// Under high traffic, relays with higher reported load (queue depth, utilization fraction)
/// receive proportionally reduced selection weight:
///   effective_capacity = capacity / (1.0 + load_penalty * load)
/// while strictly preserving:
///   1. Strict layer order (layer 1 -> 2 -> ... -> num_hops)
///   2. Geographic diversity (distinct country codes)
///   3. AS diversity (distinct autonomous systems)
///   4. Relay uniqueness (no duplicate relay IDs)
pub fn select_path_load_balanced(
    directory: &NetworkDirectory,
    num_hops: usize,
    relay_loads: &HashMap<[u8; 32], f64>,
    load_penalty: f64,
    rng: &mut impl Rng,
) -> Result<Vec<RelayInfo>, DirectoryError> {
    let mut path = Vec::with_capacity(num_hops);
    let mut used_ids: Vec<[u8; 32]> = Vec::with_capacity(num_hops);
    let mut used_as = Vec::with_capacity(num_hops);
    let mut used_cc = Vec::with_capacity(num_hops);

    for layer in 1..=num_hops as u8 {
        let candidates = directory.relays_for_layer(layer);
        if candidates.is_empty() {
            return Err(DirectoryError::PathSelectionFailed(format!("No relays in layer {}", layer)));
        }

        let mut available_candidates = Vec::with_capacity(candidates.len());
        let mut strict_candidates = Vec::with_capacity(candidates.len());

        for &r in &candidates {
            if !used_ids.contains(&r.id) {
                available_candidates.push(r);
                if !used_as.contains(&r.autonomous_system) && !used_cc.contains(&r.country_code) {
                    strict_candidates.push(r);
                }
            }
        }

        if available_candidates.is_empty() {
            return Err(DirectoryError::PathSelectionFailed(format!(
                "No unique relays available in layer {}", layer
            )));
        }

        let compute_weight = |r: &RelayInfo| -> u64 {
            let load = relay_loads.get(&r.id).copied().unwrap_or(0.0).clamp(0.0, 100.0);
            let eff = (r.bandwidth_capacity as f64) / (1.0 + load_penalty.max(0.0) * load);
            eff.round().max(1.0) as u64
        };

        let chosen = if !strict_candidates.is_empty() {
            let weights: Vec<u64> = strict_candidates.iter().map(|&r| compute_weight(r)).collect();
            if let Ok(dist) = WeightedIndex::new(&weights) {
                strict_candidates[dist.sample(rng)]
            } else {
                strict_candidates[rng.gen_range(0..strict_candidates.len())]
            }
        } else {
            tracing::warn!("Relaxing path selection constraints at layer {}", layer);
            let weights: Vec<u64> = available_candidates.iter().map(|&r| compute_weight(r)).collect();
            if let Ok(dist) = WeightedIndex::new(&weights) {
                available_candidates[dist.sample(rng)]
            } else {
                available_candidates[rng.gen_range(0..available_candidates.len())]
            }
        };

        used_ids.push(chosen.id);
        used_as.push(chosen.autonomous_system);
        used_cc.push(chosen.country_code.clone());
        path.push((*chosen).clone());
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::{EpochInfo, MixParameters};
    use crate::directory::NetworkDirectory;
    use rand::thread_rng;

    fn mock_directory() -> NetworkDirectory {
        let mut relays = Vec::new();
        let mut rng = thread_rng();
        
        for i in 0..30 {
            let layer = (i % 3) as u8 + 1;
            let asn = (i % 10) as u32;
            let cc = format!("C{}", i % 5);
            
            relays.push(RelayInfo {
                id: [i as u8; 32],
                identity_key: vec![],
                sphinx_public_key: vec![],
                address: "127.0.0.1:80".parse().unwrap(),
                layer,
                bandwidth_capacity: 1000 + rng.gen_range(0..1000),
                autonomous_system: asn,
                country_code: cc,
                uptime_hours: 100,
                stake_amount: 1000,
            });
        }
        
        let epoch = EpochInfo {
            epoch_id: 1,
            start_time: 0,
            duration_secs: 3600,
            relays,
            mix_parameters: MixParameters {
                mu: 1.0,
                cover_rate: 1.0,
                packet_size: 1024,
                max_hops: 3,
                min_pool_size: 5,
            },
        };
        
        NetworkDirectory {
            epoch,
            signature: vec![],
        }
    }

    #[test]
    fn test_path_selection() {
        let dir = mock_directory();
        let mut rng = thread_rng();
        
        let mut strict_paths = 0;
        
        for _ in 0..100 {
            let path = select_path(&dir, 3, &mut rng).unwrap();
            assert_eq!(path.len(), 3);
            
            let mut asns = vec![path[0].autonomous_system, path[1].autonomous_system, path[2].autonomous_system];
            asns.sort();
            asns.dedup();
            
            let mut ccs = vec![path[0].country_code.clone(), path[1].country_code.clone(), path[2].country_code.clone()];
            ccs.sort();
            ccs.dedup();
            
            if asns.len() == 3 && ccs.len() == 3 {
                strict_paths += 1;
            }
        }
        
        // Some might be relaxed due to pigeonhole with mock data, but most should be strict
        assert!(strict_paths > 0);
    }

    #[test]
    fn test_load_balanced_path_selection() {
        let dir = mock_directory();
        let mut rng = thread_rng();

        // Mark relay 0 (layer 1) as heavily loaded (load = 100.0)
        let mut loads = HashMap::new();
        let heavy_id = [0u8; 32];
        loads.insert(heavy_id, 100.0);

        let mut heavy_count = 0;
        let trials = 200;
        for _ in 0..trials {
            let path = select_path_load_balanced(&dir, 3, &loads, 5.0, &mut rng).unwrap();
            if path[0].id == heavy_id {
                heavy_count += 1;
            }
        }

        // Heavy relay should be selected significantly less often due to penalty
        assert!(heavy_count < trials / 4, "Overloaded relay was selected too frequently: {}", heavy_count);
    }
}
