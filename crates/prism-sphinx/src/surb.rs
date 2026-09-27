//! Single-Use Reply Blocks (SURBs).
//!
//! A SURB allows a recipient to send a reply to the original sender without
//! knowing the sender's identity or network location. The sender creates a SURB
//! containing a pre-built Sphinx header routed back to the sender. The recipient
//! uses the SURB to wrap their reply message.

use crate::constants::*;
use crate::errors::SphinxError;
use crate::header::{build_header, SphinxHeader};
use crate::routing::RouteHop;

/// A Single-Use Reply Block.
///
/// Contains a pre-built Sphinx header for the reply path and the symmetric
/// key the sender will use to decrypt the reply payload.
#[derive(Debug, Clone)]
pub struct Surb {
    /// Pre-built Sphinx header for the reply route.
    pub header: SphinxHeader,
    /// Shared secrets for each hop (needed by the sender to decrypt the reply).
    /// These are NOT transmitted — only the sender retains them.
    pub shared_secrets: Vec<[u8; 32]>,
    /// The first-hop address for the reply (so the recipient knows where to send).
    pub first_hop_address: std::net::SocketAddr,
}

impl Surb {
    /// Create a new SURB for a given reply route.
    ///
    /// The reply route goes from the recipient back to the sender.
    /// The sender creates this and attaches it to their outgoing message.
    pub fn create(
        reply_route: &[RouteHop],
        epoch_id: u32,
    ) -> Result<Self, SphinxError> {
        if reply_route.is_empty() {
            return Err(SphinxError::SurbError("reply route must have at least one hop".into()));
        }

        let first_hop_address = reply_route[0].routing.next_hop;

        // Build a Sphinx header for the reply route
        let (header, shared_secrets) = build_header(reply_route, epoch_id)?;

        Ok(Surb {
            header,
            shared_secrets,
            first_hop_address,
        })
    }

    /// Serialize the transmittable part of the SURB (header + first_hop_address).
    /// The shared_secrets are NOT included — they are retained by the sender.
    pub fn to_transmit_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + 18); // 18 = max socket addr
        buf.extend_from_slice(&self.header.to_bytes());

        // Serialize first_hop_address
        match self.first_hop_address {
            std::net::SocketAddr::V4(addr) => {
                buf.push(4); // IPv4 marker
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(addr) => {
                buf.push(6); // IPv6 marker
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        buf
    }

    /// Deserialize the transmittable part of a SURB (recipient side).
    /// Returns a PartialSurb without shared_secrets (the recipient doesn't have them).
    pub fn from_transmit_bytes(data: &[u8]) -> Result<PartialSurb, SphinxError> {
        if data.len() < HEADER_SIZE + 7 {
            return Err(SphinxError::SurbError("SURB data too short".into()));
        }

        let header = SphinxHeader::from_bytes(&data[0..HEADER_SIZE])?;

        let addr_start = HEADER_SIZE;
        let addr_type = data[addr_start];

        let first_hop_address = match addr_type {
            4 => {
                if data.len() < addr_start + 7 {
                    return Err(SphinxError::SurbError("SURB IPv4 address truncated".into()));
                }
                let ip = std::net::Ipv4Addr::new(
                    data[addr_start + 1],
                    data[addr_start + 2],
                    data[addr_start + 3],
                    data[addr_start + 4],
                );
                let port = u16::from_be_bytes([data[addr_start + 5], data[addr_start + 6]]);
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port))
            }
            6 => {
                if data.len() < addr_start + 19 {
                    return Err(SphinxError::SurbError("SURB IPv6 address truncated".into()));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[addr_start + 1..addr_start + 17]);
                let ip = std::net::Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([data[addr_start + 17], data[addr_start + 18]]);
                std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0))
            }
            _ => {
                return Err(SphinxError::SurbError(format!(
                    "unknown address type: {}",
                    addr_type
                )));
            }
        };

        Ok(PartialSurb {
            header,
            first_hop_address,
        })
    }
}

/// A SURB as received by the recipient (without the shared secrets).
#[derive(Debug, Clone)]
pub struct PartialSurb {
    /// Pre-built Sphinx header for the reply route.
    pub header: SphinxHeader,
    /// Address of the first hop relay for sending the reply.
    pub first_hop_address: std::net::SocketAddr,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{PacketFlag, RoutingInfo};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

    fn make_reply_route(num_hops: usize) -> Vec<RouteHop> {
        (0..num_hops)
            .map(|i| {
                let sk = X25519Secret::random_from_rng(rand::thread_rng());
                let pk = X25519Public::from(&sk);

                RouteHop {
                    routing: RoutingInfo {
                        next_hop: SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::new(10, 1, 0, (i + 1) as u8),
                            8000 + i as u16,
                        )),
                        delay_seed: 0,
                        flag: if i == num_hops - 1 {
                            PacketFlag::FinalHop
                        } else {
                            PacketFlag::Forward
                        },
                        reserved: 0,
                    },
                    public_key: pk.to_bytes(),
                }
            })
            .collect()
    }

    #[test]
    fn surb_creation() {
        let route = make_reply_route(3);
        let surb = Surb::create(&route, 1).unwrap();

        assert_eq!(surb.shared_secrets.len(), 3);
        assert_eq!(surb.header.version, PROTOCOL_VERSION);
    }

    #[test]
    fn surb_serialization_roundtrip() {
        let route = make_reply_route(3);
        let surb = Surb::create(&route, 1).unwrap();

        let bytes = surb.to_transmit_bytes();
        let partial = Surb::from_transmit_bytes(&bytes).unwrap();

        assert_eq!(partial.header.version, surb.header.version);
        assert_eq!(partial.header.epoch_id, surb.header.epoch_id);
        assert_eq!(partial.first_hop_address, surb.first_hop_address);
    }

    #[test]
    fn surb_empty_route_fails() {
        let result = Surb::create(&[], 1);
        assert!(result.is_err());
    }
}
