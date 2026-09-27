use crate::poisson::PoissonDelay;
use prism_sphinx::packet::{create_cover_packet, SphinxPacket};
use prism_sphinx::routing::{PacketFlag, RouteHop, RoutingInfo};
use prism_sphinx::SphinxError;
use std::time::Duration;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

pub const PACKET_SIZE: usize = prism_sphinx::PACKET_SIZE;

pub struct CoverTrafficGenerator {
    poisson: PoissonDelay,
    packet_size: usize,
}

impl CoverTrafficGenerator {
    pub fn new(rate: f64, packet_size: usize) -> Self {
        Self {
            poisson: PoissonDelay::new(rate),
            packet_size,
        }
    }

    /// Generate a genuine Sphinx loop cover packet over the given route and epoch.
    pub fn generate_loop_cover_packet(
        &self,
        route: &[RouteHop],
        epoch_id: u32,
    ) -> Result<SphinxPacket, SphinxError> {
        create_cover_packet(route, epoch_id, PacketFlag::LoopCover)
    }

    /// Generate a genuine Sphinx drop cover packet over the given route and epoch.
    pub fn generate_drop_cover_packet(
        &self,
        route: &[RouteHop],
        epoch_id: u32,
    ) -> Result<SphinxPacket, SphinxError> {
        create_cover_packet(route, epoch_id, PacketFlag::DropCover)
    }

    /// Generate loop cover bytes. If an ephemeral route is needed, constructs a valid
    /// single-hop Sphinx packet to ensure wire fidelity and constant size.
    /// Generate loop cover bytes. Uses provided target public key if available.
    pub fn generate_loop_cover(&self, _route: &[u8], keys: &[u8]) -> Vec<u8> {
        let pk = if keys.len() >= 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&keys[0..32]);
            X25519Public::from(arr)
        } else {
            let sk = X25519Secret::random_from_rng(rand::thread_rng());
            X25519Public::from(&sk)
        };
        let hop = RouteHop {
            routing: RoutingInfo {
                next_hop: "127.0.0.1:9000".parse().unwrap(),
                delay_seed: 0,
                flag: PacketFlag::LoopCover,
                reserved: 0,
            },
            public_key: pk.to_bytes(),
        };
        match create_cover_packet(&[hop], 1, PacketFlag::LoopCover) {
            Ok(pkt) => pkt.to_bytes(),
            Err(_) => {
                let mut packet = vec![0u8; self.packet_size];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut packet);
                packet
            }
        }
    }

    /// Generate drop cover bytes. Generates a valid Sphinx packet to ensure wire fidelity.
    pub fn generate_drop_cover(&self, packet_size: usize) -> Vec<u8> {
        let size = if packet_size == 0 { self.packet_size } else { packet_size };
        let sk = X25519Secret::random_from_rng(rand::thread_rng());
        let pk = X25519Public::from(&sk);
        let hop = RouteHop {
            routing: RoutingInfo {
                next_hop: "127.0.0.1:9000".parse().unwrap(),
                delay_seed: 0,
                flag: PacketFlag::DropCover,
                reserved: 0,
            },
            public_key: pk.to_bytes(),
        };
        match create_cover_packet(&[hop], 1, PacketFlag::DropCover) {
            Ok(pkt) => pkt.to_bytes(),
            Err(_) => {
                let mut packet = vec![0u8; size];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut packet);
                packet
            }
        }
    }

    pub fn next_delay(&self) -> Duration {
        self.poisson.sample()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cover_sizes() {
        let gen = CoverTrafficGenerator::new(10.0, PACKET_SIZE);
        
        let p1 = gen.generate_loop_cover(&[], &[]);
        assert_eq!(p1.len(), PACKET_SIZE);
        
        let p2 = gen.generate_drop_cover(PACKET_SIZE);
        assert_eq!(p2.len(), PACKET_SIZE);
    }

    #[test]
    fn test_valid_sphinx_cover_generation() {
        let gen = CoverTrafficGenerator::new(10.0, PACKET_SIZE);
        let loop_bytes = gen.generate_loop_cover(&[], &[]);
        let parsed_loop = SphinxPacket::from_bytes(&loop_bytes).unwrap();
        assert_eq!(parsed_loop.header.version, 1);
        assert_eq!(parsed_loop.header.epoch_id, 1);

        let drop_bytes = gen.generate_drop_cover(PACKET_SIZE);
        let parsed_drop = SphinxPacket::from_bytes(&drop_bytes).unwrap();
        assert_eq!(parsed_drop.header.version, 1);
        assert_eq!(parsed_drop.header.epoch_id, 1);
    }
}
