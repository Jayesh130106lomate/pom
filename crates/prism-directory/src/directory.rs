use crate::epoch::EpochInfo;
use crate::relay_info::RelayInfo;

pub struct NetworkDirectory {
    pub epoch: EpochInfo,
    pub signature: Vec<u8>,
}

impl NetworkDirectory {
    pub fn relays_for_layer(&self, layer: u8) -> Vec<&RelayInfo> {
        self.epoch.relays.iter().filter(|r| r.layer == layer).collect()
    }

    pub fn relay_by_id(&self, id: &[u8; 32]) -> Option<&RelayInfo> {
        self.epoch.relays.iter().find(|r| &r.id == id)
    }

    pub fn total_relays(&self) -> usize {
        self.epoch.relays.len()
    }

    pub fn layers(&self) -> Vec<u8> {
        let mut l: Vec<u8> = self.epoch.relays.iter().map(|r| r.layer).collect();
        l.sort_unstable();
        l.dedup();
        l
    }
}
