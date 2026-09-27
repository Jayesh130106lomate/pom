use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Error returned when MixPool operations fail.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum PoolError {
    #[error("mix pool capacity exceeded: current {current}, max {max}")]
    CapacityExceeded { current: usize, max: usize },
}

pub struct MixPool<T = Vec<u8>> {
    pool: BTreeMap<Instant, Vec<T>>,
    min_pool_size: usize,
    max_capacity: usize,
    current_size: usize,
}

impl<T> MixPool<T> {
    pub fn new() -> Self {
        Self {
            pool: BTreeMap::new(),
            min_pool_size: 0,
            max_capacity: 10_000,
            current_size: 0,
        }
    }

    pub fn with_min_size(min_pool_size: usize) -> Self {
        Self {
            pool: BTreeMap::new(),
            min_pool_size,
            max_capacity: 10_000,
            current_size: 0,
        }
    }

    pub fn with_capacities(min_pool_size: usize, max_capacity: usize) -> Self {
        Self {
            pool: BTreeMap::new(),
            min_pool_size,
            max_capacity,
            current_size: 0,
        }
    }

    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    pub fn set_max_capacity(&mut self, max: usize) {
        self.max_capacity = max;
    }

    pub fn is_full(&self) -> bool {
        self.current_size >= self.max_capacity
    }

    pub fn available_capacity(&self) -> usize {
        self.max_capacity.saturating_sub(self.current_size)
    }

    pub fn capacity_utilization(&self) -> f64 {
        if self.max_capacity == 0 {
            1.0
        } else {
            (self.current_size as f64 / self.max_capacity as f64).min(1.0)
        }
    }

    pub fn insert(&mut self, item: T, delay: Duration) -> Result<(), PoolError> {
        if self.current_size >= self.max_capacity {
            return Err(PoolError::CapacityExceeded {
                current: self.current_size,
                max: self.max_capacity,
            });
        }
        let departure_time = Instant::now() + delay;
        self.pool.entry(departure_time).or_default().push(item);
        self.current_size += 1;
        Ok(())
    }

    pub fn drain_ready(&mut self) -> Vec<T> {
        let now = Instant::now();
        let mut ready = Vec::new();
        
        let mut to_remove = Vec::new();
        for (time, items) in self.pool.iter_mut() {
            if *time <= now {
                let available_to_drain = self.current_size.saturating_sub(self.min_pool_size);
                if available_to_drain == 0 {
                    break;
                }
                
                let drain_count = std::cmp::min(available_to_drain, items.len());
                ready.extend(items.drain(..drain_count));
                self.current_size -= drain_count;
                
                if items.is_empty() {
                    to_remove.push(*time);
                }
                
                if self.current_size <= self.min_pool_size {
                    break;
                }
            } else {
                break; // Because it's a BTreeMap, times are ordered
            }
        }
        
        for time in to_remove {
            self.pool.remove(&time);
        }
        
        ready
    }

    pub fn insert_adaptive(&mut self, item: T, adaptive: &crate::poisson::AdaptivePoissonDelay) -> Result<(), PoolError> {
        let delay = adaptive.sample_for_pool(self.current_size);
        self.insert(item, delay)
    }

    pub fn insert_batch(&mut self, items: Vec<(T, Duration)>) -> Result<(), PoolError> {
        if self.current_size + items.len() > self.max_capacity {
            return Err(PoolError::CapacityExceeded {
                current: self.current_size + items.len(),
                max: self.max_capacity,
            });
        }
        let now = Instant::now();
        for (item, delay) in items {
            let departure_time = now + delay;
            self.pool.entry(departure_time).or_default().push(item);
            self.current_size += 1;
        }
        Ok(())
    }

    pub fn drain_ready_batch(&mut self, max_batch: usize) -> Vec<T> {
        if max_batch == 0 {
            return Vec::new();
        }

        let now = Instant::now();
        let mut ready = Vec::new();
        let mut to_remove = Vec::new();

        for (time, items) in self.pool.iter_mut() {
            if *time <= now {
                let available_to_drain = self.current_size.saturating_sub(self.min_pool_size);
                if available_to_drain == 0 {
                    break;
                }

                let remaining_capacity = max_batch.saturating_sub(ready.len());
                if remaining_capacity == 0 {
                    break;
                }

                let drain_count = std::cmp::min(std::cmp::min(available_to_drain, items.len()), remaining_capacity);
                ready.extend(items.drain(..drain_count));
                self.current_size -= drain_count;

                if items.is_empty() {
                    to_remove.push(*time);
                }

                if self.current_size <= self.min_pool_size || ready.len() >= max_batch {
                    break;
                }
            } else {
                break;
            }
        }

        for time in to_remove {
            self.pool.remove(&time);
        }

        ready
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.pool.keys().next().copied()
    }

    pub fn len(&self) -> usize {
        self.current_size
    }
    
    pub fn queue_depth(&self) -> usize {
        self.current_size
    }

    pub fn is_empty(&self) -> bool {
        self.current_size == 0
    }

    pub fn min_pool_size(&self) -> usize {
        self.min_pool_size
    }

    pub fn set_min_pool_size(&mut self, min: usize) {
        self.min_pool_size = min;
    }

    pub fn peek_ready_count(&self, now: Instant) -> usize {
        let mut count = 0;
        for (time, items) in self.pool.iter() {
            if *time <= now {
                count += items.len();
            } else {
                break;
            }
        }
        let available = self.current_size.saturating_sub(self.min_pool_size);
        std::cmp::min(count, available)
    }
}

impl<T> Default for MixPool<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_pool_ordering_and_min_size() {
        let mut pool = MixPool::new();
        pool.set_min_pool_size(5);
        
        for i in 0..20 {
            let delay = Duration::from_millis((20 - i) * 10);
            pool.insert(vec![i as u8], delay).unwrap();
        }
        
        assert_eq!(pool.len(), 20);
        
        // Let all packets mature
        sleep(Duration::from_millis(250));
        
        let drained = pool.drain_ready();
        assert_eq!(drained.len(), 15); // Left 5 in pool
        assert_eq!(pool.len(), 5);
        
        // The earliest departures come out first (smallest delay).
        // The smallest delay was i=19 (10ms).
        assert_eq!(drained[0][0], 19);
    }

    #[test]
    fn test_pool_drain_ready_batch() {
        let mut pool = MixPool::new();
        pool.set_min_pool_size(2);

        let items: Vec<(Vec<u8>, Duration)> = (0..10)
            .map(|i| (vec![i as u8], Duration::from_millis(1)))
            .collect();
        pool.insert_batch(items).unwrap();
        assert_eq!(pool.len(), 10);

        sleep(Duration::from_millis(10));

        // Available to drain = 10 - 2 = 8.
        // Drain batch of 3:
        let b1 = pool.drain_ready_batch(3);
        assert_eq!(b1.len(), 3);
        assert_eq!(pool.len(), 7);

        // Drain batch of 10 (should drain remaining 5, leaving 2):
        let b2 = pool.drain_ready_batch(10);
        assert_eq!(b2.len(), 5);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_pool_adaptive_insert() {
        use crate::poisson::AdaptivePoissonDelay;
        let adaptive = AdaptivePoissonDelay::new(10.0, 100.0, 5);
        let mut pool = MixPool::new();
        pool.set_min_pool_size(3);

        for i in 0..15 {
            pool.insert_adaptive(vec![i as u8], &adaptive).unwrap();
        }
        assert_eq!(pool.len(), 15);
        assert_eq!(pool.queue_depth(), 15);
    }

    #[test]
    fn test_mixpool_bounded_capacity_and_overflow() {
        let mut pool = MixPool::with_capacities(1, 5);
        assert_eq!(pool.max_capacity(), 5);
        assert!(!pool.is_full());
        assert_eq!(pool.available_capacity(), 5);

        for i in 0..5 {
            assert!(pool.insert(vec![i], Duration::from_secs(1)).is_ok());
        }
        assert!(pool.is_full());
        assert_eq!(pool.available_capacity(), 0);
        assert!((pool.capacity_utilization() - 1.0).abs() < 1e-6);

        // 6th insert must return CapacityExceeded
        let overflow = pool.insert(vec![6], Duration::from_secs(1));
        assert_eq!(
            overflow,
            Err(PoolError::CapacityExceeded { current: 5, max: 5 })
        );

        // Batch overflow
        let batch_overflow = pool.insert_batch(vec![(vec![7], Duration::from_secs(1))]);
        assert!(batch_overflow.is_err());
    }
}
