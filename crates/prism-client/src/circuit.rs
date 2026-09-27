//! Client-side circuit construction.
//!
//! Builds Sphinx packets for sending through a configured route.

use std::net::SocketAddr;

use prism_sphinx::fragment::Fragmenter;
use prism_sphinx::packet::{create_cover_packet, create_sphinx_packet, SphinxPacket};
use prism_sphinx::routing::{PacketFlag, RouteHop};
use prism_sphinx::surb::Surb;

/// A circuit through the mix network.
#[derive(Debug, Clone)]
pub struct Circuit {
    /// The route hops.
    pub route: Vec<RouteHop>,
    /// Current epoch.
    pub epoch_id: u32,
    /// Address of the first relay.
    pub entry_address: SocketAddr,
}

impl Circuit {
    /// Create a new circuit with an explicit entry relay address.
    pub fn new(entry_address: SocketAddr, route: Vec<RouteHop>, epoch_id: u32) -> Self {
        Circuit {
            route,
            epoch_id,
            entry_address,
        }
    }

    /// Create a new circuit with an explicit entry relay address (alias for backward compatibility).
    pub fn new_with_entry(entry_address: SocketAddr, route: Vec<RouteHop>, epoch_id: u32) -> Self {
        Self::new(entry_address, route, epoch_id)
    }

    /// Build a single Sphinx packet for a message through this circuit.
    pub fn wrap_message(&self, message: &[u8]) -> Result<SphinxPacket, prism_sphinx::SphinxError> {
        create_sphinx_packet(message, &self.route, self.epoch_id)
    }

    /// Build Sphinx packets for a message through this circuit, automatically fragmenting if needed.
    pub fn wrap_message_auto(&self, message: &[u8]) -> Result<Vec<SphinxPacket>, prism_sphinx::SphinxError> {
        if message.len() <= prism_sphinx::constants::MAX_PAYLOAD_DATA {
            Ok(vec![self.wrap_message(message)?])
        } else {
            let fragments = Fragmenter::fragment(message)?;
            let mut packets = Vec::with_capacity(fragments.len());
            for frag in fragments {
                packets.push(create_sphinx_packet(&frag.to_payload(), &self.route, self.epoch_id)?);
            }
            Ok(packets)
        }
    }

    /// Build a cover traffic packet through this circuit.
    #[allow(dead_code)]
    pub fn wrap_cover(&self, flag: PacketFlag) -> Result<SphinxPacket, prism_sphinx::SphinxError> {
        create_cover_packet(&self.route, self.epoch_id, flag)
    }

    /// Create a SURB for receiving replies through this circuit.
    #[allow(dead_code)]
    pub fn create_surb(&self) -> Result<Surb, prism_sphinx::SphinxError> {
        Surb::create(&self.route, self.epoch_id)
    }
}
