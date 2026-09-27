use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify};
use std::sync::Arc;

pub struct PacketScheduler {
    queue: Arc<Mutex<BTreeMap<Instant, Vec<Vec<u8>>>>>,
    notify: Arc<Notify>,
}

impl PacketScheduler {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(BTreeMap::new())),
            notify: Arc::new(Notify::new()),
        }
    }

    pub async fn schedule(&self, packet: Vec<u8>, delay: Duration) {
        let dep_time = Instant::now() + delay;
        let mut q = self.queue.lock().await;
        q.entry(dep_time).or_default().push(packet);
        self.notify.notify_one();
    }

    pub async fn next_packet(&self) -> Vec<u8> {
        loop {
            let now = Instant::now();
            let sleep_duration = {
                let mut q = self.queue.lock().await;
                if let Some((&time, packets)) = q.iter_mut().next() {
                    if time <= now {
                        let packet = packets.remove(0);
                        if packets.is_empty() {
                            q.remove(&time);
                        }
                        return packet;
                    } else {
                        Some(time - now)
                    }
                } else {
                    None
                }
            };

            if let Some(dur) = sleep_duration {
                tokio::select! {
                    _ = tokio::time::sleep(dur) => {},
                    _ = self.notify.notified() => {},
                }
            } else {
                self.notify.notified().await;
            }
        }
    }
}

impl Default for PacketScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_scheduler_ordering() {
        let scheduler = PacketScheduler::new();
        
        let start = Instant::now();
        scheduler.schedule(vec![1], Duration::from_millis(50)).await;
        scheduler.schedule(vec![2], Duration::from_millis(150)).await;
        scheduler.schedule(vec![3], Duration::from_millis(100)).await;
        
        let p1 = scheduler.next_packet().await;
        assert_eq!(p1, vec![1]);
        assert!(start.elapsed() >= Duration::from_millis(50));
        
        let p2 = scheduler.next_packet().await;
        assert_eq!(p2, vec![3]);
        assert!(start.elapsed() >= Duration::from_millis(100));
        
        let p3 = scheduler.next_packet().await;
        assert_eq!(p3, vec![2]);
        assert!(start.elapsed() >= Duration::from_millis(150));
    }
}
