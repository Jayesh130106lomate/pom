//! Routing information encoding for Sphinx headers.
//!
//! Each hop in the Sphinx route has a routing block containing:
//! - The next hop's network address
//! - A delay seed for Poisson mixing
//! - Flags indicating packet type
//! - A MAC for integrity verification

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Flags for routing commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum PacketFlag {
    /// Normal forward packet.
    Forward = 0x0001,
    /// Loop cover traffic (returns to sender).
    LoopCover = 0x0002,
    /// Drop cover traffic (silently discarded at destination).
    DropCover = 0x0003,
    /// Final destination (this is the last hop).
    FinalHop = 0x0004,
    /// SURB-based reply packet.
    SurbReply = 0x0005,
}

impl PacketFlag {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Forward),
            2 => Some(Self::LoopCover),
            3 => Some(Self::DropCover),
            4 => Some(Self::FinalHop),
            5 => Some(Self::SurbReply),
            _ => None,
        }
    }

    pub fn from_u16(v: u16) -> Option<Self> {
        Self::from_u8(v as u8)
    }
}

/// A single hop's routing information (plaintext, before encryption).
#[derive(Debug, Clone)]
pub struct RoutingInfo {
    /// Network address of the next hop (or final destination info).
    pub next_hop: SocketAddr,
    /// Seed for computing the Poisson mixing delay at this hop.
    pub delay_seed: u32,
    /// Packet type flags.
    pub flag: PacketFlag,
    /// Reserved for future use.
    pub reserved: u16,
}

impl RoutingInfo {
    /// Serialize to fixed-size byte array (24 bytes).
    /// Layout:
    ///   [0]      Address family: 0 = IPv4, 1 = IPv6
    ///   [1]      PacketFlag (u8)
    ///   [2..6]   Delay seed (u32, big-endian)
    ///   If IPv4:
    ///     [6..10]  IPv4 octets (4 bytes)
    ///     [10..12] Port (u16, big-endian)
    ///     [12..24] Zero padding (12 bytes)
    ///   If IPv6:
    ///     [6..22]  IPv6 octets (16 bytes)
    ///     [22..24] Port (u16, big-endian)
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[1] = self.flag as u8;
        buf[2..6].copy_from_slice(&self.delay_seed.to_be_bytes());

        match self.next_hop {
            SocketAddr::V4(addr) => {
                buf[0] = 0;
                buf[6..10].copy_from_slice(&addr.ip().octets());
                buf[10..12].copy_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                buf[0] = 1;
                buf[6..22].copy_from_slice(&addr.ip().octets());
                buf[22..24].copy_from_slice(&addr.port().to_be_bytes());
            }
        }

        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(buf: &[u8; 24]) -> Option<Self> {
        let addr_type = buf[0];
        let flag = PacketFlag::from_u8(buf[1])?;
        let delay_seed = u32::from_be_bytes(buf[2..6].try_into().ok()?);

        let next_hop = if addr_type == 0 {
            let ip_bytes: [u8; 4] = buf[6..10].try_into().ok()?;
            let port = u16::from_be_bytes(buf[10..12].try_into().ok()?);
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip_bytes)), port)
        } else if addr_type == 1 {
            let ip_bytes: [u8; 16] = buf[6..22].try_into().ok()?;
            let port = u16::from_be_bytes(buf[22..24].try_into().ok()?);
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes)), port)
        } else {
            return None;
        };

        Some(RoutingInfo {
            next_hop,
            delay_seed,
            flag,
            reserved: 0,
        })
    }
}

/// A complete route specification for Sphinx packet construction.
#[derive(Debug, Clone)]
pub struct Route {
    /// The hops in order (first hop to last hop).
    pub hops: Vec<RouteHop>,
}

/// A single hop in a route, including routing info and the relay's public key.
#[derive(Debug, Clone)]
pub struct RouteHop {
    /// Routing information for this hop.
    pub routing: RoutingInfo,
    /// The relay's X25519 public key for this epoch.
    pub public_key: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn routing_info_roundtrip() {
        let info = RoutingInfo {
            next_hop: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 9001)),
            delay_seed: 42,
            flag: PacketFlag::Forward,
            reserved: 0,
        };

        let bytes = info.to_bytes();
        let recovered = RoutingInfo::from_bytes(&bytes).expect("deserialization failed");

        assert_eq!(recovered.next_hop, info.next_hop);
        assert_eq!(recovered.delay_seed, 42);
        assert_eq!(recovered.flag, PacketFlag::Forward);
    }

    #[test]
    fn routing_info_all_flags() {
        let flags = [
            PacketFlag::Forward,
            PacketFlag::LoopCover,
            PacketFlag::DropCover,
            PacketFlag::FinalHop,
            PacketFlag::SurbReply,
        ];

        for flag in flags {
            let info = RoutingInfo {
                next_hop: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
                delay_seed: 0,
                flag,
                reserved: 0,
            };
            let bytes = info.to_bytes();
            let recovered = RoutingInfo::from_bytes(&bytes).unwrap();
            assert_eq!(recovered.flag, flag);
        }
    }

    #[test]
    fn routing_info_ipv6_roundtrip() {
        use std::net::{Ipv6Addr, SocketAddrV6};

        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0, 0, 0x8a2e, 0x370, 0x7334);
        let info = RoutingInfo {
            next_hop: SocketAddr::V6(SocketAddrV6::new(ipv6, 9050, 0, 0)),
            delay_seed: 999,
            flag: PacketFlag::FinalHop,
            reserved: 0,
        };

        let bytes = info.to_bytes();
        let recovered = RoutingInfo::from_bytes(&bytes).expect("IPv6 deserialization failed");

        assert_eq!(recovered.next_hop, info.next_hop);
        assert_eq!(recovered.delay_seed, 999);
        assert_eq!(recovered.flag, PacketFlag::FinalHop);
    }
}
