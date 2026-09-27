//! Complete Sphinx packet — header + payload combined.
//!
//! This module provides the top-level API for constructing and processing
//! complete Sphinx packets. Every packet is exactly PACKET_SIZE bytes,
//! regardless of hop count or message size.

use crate::constants::*;
use crate::errors::SphinxError;
use crate::header::{build_header, process_header, SphinxHeader};
use crate::payload::{
    decrypt_inner_payload, decrypt_payload_layer, derive_inner_aead_key_and_nonce,
    encrypt_inner_payload, encrypt_payload_layer, pad_payload, unpad_payload,
};
use crate::routing::{PacketFlag, RouteHop};

/// A complete Sphinx packet (header + encrypted payload).
#[derive(Debug, Clone)]
pub struct SphinxPacket {
    /// The Sphinx header.
    pub header: SphinxHeader,
    /// The encrypted payload (size-preserving layered encryption).
    pub payload: Vec<u8>,
}

impl SphinxPacket {
    /// Serialize to exactly PACKET_SIZE bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PACKET_SIZE);
        buf.extend_from_slice(&self.header.to_bytes());

        if self.payload.len() >= PAYLOAD_SIZE {
            buf.extend_from_slice(&self.payload[..PAYLOAD_SIZE]);
        } else {
            buf.extend_from_slice(&self.payload);
            buf.resize(PACKET_SIZE, 0);
        }

        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, SphinxError> {
        if data.len() != PACKET_SIZE {
            return Err(SphinxError::InvalidPacketSize {
                expected: PACKET_SIZE,
                got: data.len(),
            });
        }

        let header = SphinxHeader::from_bytes(&data[0..HEADER_SIZE])?;
        let payload = data[HEADER_SIZE..].to_vec();

        Ok(SphinxPacket { header, payload })
    }
}

/// Result of processing a Sphinx packet at a relay.
pub enum ProcessedPacket {
    /// Forward to the next relay.
    Forward {
        /// Network address of the next hop.
        next_hop: std::net::SocketAddr,
        /// Delay seed for Poisson mixing.
        delay_seed: u32,
        /// The packet to forward (with one layer stripped).
        packet: SphinxPacket,
        /// Shared secret for this hop (for replay detection).
        shared_secret: [u8; 32],
    },
    /// This is the final destination — deliver the payload.
    Destination {
        /// The decrypted message payload.
        payload: Vec<u8>,
        /// Shared secret for replay detection.
        shared_secret: [u8; 32],
    },
    /// Loop cover traffic (forwarded along loop route back to originator or terminated).
    LoopCover {
        /// Network address of the next hop.
        next_hop: std::net::SocketAddr,
        /// Delay seed for Poisson mixing.
        delay_seed: u32,
        /// The packet to forward along loop path (with one layer stripped).
        packet: SphinxPacket,
        /// Shared secret for this hop (for replay detection).
        shared_secret: [u8; 32],
    },
    /// Drop cover — discard silently.
    DropCover {
        shared_secret: [u8; 32],
    },
}

/// Construct a complete Sphinx packet for a message.
///
/// Plaintext is padded to PAYLOAD_PLAINTEXT_SIZE (31,728 bytes) and authenticated/encrypted
/// with Inner ChaCha20-Poly1305 AEAD using keys derived from the destination shared secret.
/// Outer layers use size-preserving ChaCha20 stream ciphers for intermediate hops.
pub fn create_sphinx_packet(
    message: &[u8],
    route: &[RouteHop],
    epoch_id: u32,
) -> Result<SphinxPacket, SphinxError> {
    // Payload capacity: PAYLOAD_PLAINTEXT_SIZE minus 4 bytes for padding length
    let available = PAYLOAD_PLAINTEXT_SIZE - 4;
    if message.len() > available {
        return Err(SphinxError::PayloadTooLarge {
            max: available,
            got: message.len(),
        });
    }

    // Build header (returns shared secrets for payload encryption)
    let (header, shared_secrets) = build_header(route, epoch_id)?;
    let num_hops = shared_secrets.len();
    let dest_secret = &shared_secrets[num_hops - 1];

    // Pad message to exactly PAYLOAD_PLAINTEXT_SIZE
    let padded = pad_payload(message, PAYLOAD_PLAINTEXT_SIZE)?;

    // Inner ChaCha20-Poly1305 AEAD encryption (produces PAYLOAD_SIZE bytes)
    let (inner_key, inner_nonce) = derive_inner_aead_key_and_nonce(dest_secret);
    let inner_ciphertext = encrypt_inner_payload(&padded, &inner_key, &inner_nonce)?;
    let mut payload = inner_ciphertext.to_vec();

    // Apply outer ChaCha20 stream cipher layers for intermediate hops (num_hops - 2 down to 0)
    if num_hops > 1 {
        for secret in shared_secrets[..num_hops - 1].iter().rev() {
            encrypt_payload_layer(secret, &mut payload);
        }
    }

    Ok(SphinxPacket { header, payload })
}

/// Process a Sphinx packet at a relay node.
///
/// Returns the processing result including shared_secret for replay detection.
/// Process a Sphinx packet in-place at a relay node, consuming the packet to avoid copying its payload.
pub fn process_sphinx_packet_in_place(
    mut packet: SphinxPacket,
    relay_secret_key: &[u8; 32],
) -> Result<ProcessedPacket, SphinxError> {
    let processed = process_header(&packet.header, relay_secret_key)?;

    match processed.routing.flag {
        PacketFlag::Forward | PacketFlag::SurbReply => {
            decrypt_payload_layer(&processed.shared_secret, &mut packet.payload);
            packet.header = processed.next_header;
            Ok(ProcessedPacket::Forward {
                next_hop: processed.routing.next_hop,
                delay_seed: processed.routing.delay_seed,
                packet,
                shared_secret: processed.shared_secret,
            })
        }
        PacketFlag::FinalHop => {
            let payload_array: &[u8; PAYLOAD_SIZE] = packet
                .payload
                .as_slice()
                .try_into()
                .map_err(|_| SphinxError::InvalidPacketSize {
                    expected: PAYLOAD_SIZE,
                    got: packet.payload.len(),
                })?;
            let (key, nonce) = derive_inner_aead_key_and_nonce(&processed.shared_secret);
            let padded_plaintext = decrypt_inner_payload(payload_array, &key, &nonce)?;
            let message = unpad_payload(&padded_plaintext)?;
            Ok(ProcessedPacket::Destination {
                payload: message,
                shared_secret: processed.shared_secret,
            })
        }
        PacketFlag::LoopCover => {
            decrypt_payload_layer(&processed.shared_secret, &mut packet.payload);
            packet.header = processed.next_header;
            Ok(ProcessedPacket::LoopCover {
                next_hop: processed.routing.next_hop,
                delay_seed: processed.routing.delay_seed,
                packet,
                shared_secret: processed.shared_secret,
            })
        }
        PacketFlag::DropCover => Ok(ProcessedPacket::DropCover {
            shared_secret: processed.shared_secret,
        }),
    }
}

/// Process a Sphinx packet at a relay node.
///
/// Returns the processing result including shared_secret for replay detection.
pub fn process_sphinx_packet(
    packet: &SphinxPacket,
    relay_secret_key: &[u8; 32],
) -> Result<ProcessedPacket, SphinxError> {
    process_sphinx_packet_in_place(packet.clone(), relay_secret_key)
}

/// Create a cover traffic packet (indistinguishable from real packets).
pub fn create_cover_packet(
    route: &[RouteHop],
    epoch_id: u32,
    flag: PacketFlag,
) -> Result<SphinxPacket, SphinxError> {
    let available = PAYLOAD_PLAINTEXT_SIZE - 4;
    let mut random_data = vec![0u8; available];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut random_data);

    let mut cover_route: Vec<RouteHop> = route.to_vec();
    if let Some(last) = cover_route.last_mut() {
        last.routing.flag = flag;
    }

    let (header, shared_secrets) = build_header(&cover_route, epoch_id)?;
    let num_hops = shared_secrets.len();
    let dest_secret = &shared_secrets[num_hops - 1];

    let padded = pad_payload(&random_data, PAYLOAD_PLAINTEXT_SIZE)?;
    let (inner_key, inner_nonce) = derive_inner_aead_key_and_nonce(dest_secret);
    let inner_ciphertext = encrypt_inner_payload(&padded, &inner_key, &inner_nonce)?;
    let mut payload = inner_ciphertext.to_vec();

    if num_hops > 1 {
        for secret in shared_secrets[..num_hops - 1].iter().rev() {
            encrypt_payload_layer(secret, &mut payload);
        }
    }

    Ok(SphinxPacket { header, payload })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::RoutingInfo;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

    fn make_test_route(num_hops: usize) -> (Vec<RouteHop>, Vec<[u8; 32]>) {
        let mut hops = Vec::new();
        let mut secret_keys = Vec::new();

        for i in 0..num_hops {
            let sk = X25519Secret::random_from_rng(rand::thread_rng());
            let pk = X25519Public::from(&sk);

            let flag = if i == num_hops - 1 {
                PacketFlag::FinalHop
            } else {
                PacketFlag::Forward
            };

            hops.push(RouteHop {
                routing: RoutingInfo {
                    next_hop: SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(10, 0, 0, (i + 1) as u8),
                        9000 + i as u16,
                    )),
                    delay_seed: (i * 100) as u32,
                    flag,
                    reserved: 0,
                },
                public_key: pk.to_bytes(),
            });

            secret_keys.push(sk.to_bytes());
        }

        (hops, secret_keys)
    }

    #[test]
    fn packet_serialization_roundtrip() {
        let (route, _sks) = make_test_route(3);
        let message = b"hello, sphinx!";

        let packet = create_sphinx_packet(message, &route, 1).unwrap();
        let bytes = packet.to_bytes();

        assert_eq!(bytes.len(), PACKET_SIZE);

        let recovered = SphinxPacket::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.header.version, PROTOCOL_VERSION);
        assert_eq!(recovered.header.epoch_id, 1);
    }

    #[test]
    fn packet_single_hop() {
        let (route, sks) = make_test_route(1);
        let message = b"single hop message";

        let packet = create_sphinx_packet(message, &route, 1).unwrap();

        let result = process_sphinx_packet(&packet, &sks[0]).unwrap();
        match result {
            ProcessedPacket::Destination { payload, .. } => {
                assert_eq!(&payload, &message.to_vec());
            }
            _ => panic!("expected Destination"),
        }
    }

    // CRITICAL TEST: Multi-hop end-to-end packet processing.
    // This is the test that was MISSING and would have caught bugs C1, C2, C6.
    #[test]
    fn packet_three_hop_end_to_end() {
        let (route, sks) = make_test_route(3);
        let message = b"hello from a 3-hop Sphinx packet!";

        let packet = create_sphinx_packet(message, &route, 1).unwrap();
        let original_size = packet.to_bytes().len();

        // Hop 0: First relay processes
        let result0 = process_sphinx_packet(&packet, &sks[0]).unwrap();
        let (next_hop_0, packet1) = match result0 {
            ProcessedPacket::Forward {
                next_hop, packet, ..
            } => (next_hop, packet),
            _ => panic!("hop 0 should forward"),
        };
        assert_eq!(next_hop_0, route[0].routing.next_hop);
        assert_eq!(packet1.to_bytes().len(), original_size, "packet size must be constant");

        // Hop 1: Second relay processes
        let result1 = process_sphinx_packet(&packet1, &sks[1]).unwrap();
        let (next_hop_1, packet2) = match result1 {
            ProcessedPacket::Forward {
                next_hop, packet, ..
            } => (next_hop, packet),
            _ => panic!("hop 1 should forward"),
        };
        assert_eq!(next_hop_1, route[1].routing.next_hop);
        assert_eq!(packet2.to_bytes().len(), original_size, "packet size must be constant");

        // Hop 2: Final relay (destination)
        let result2 = process_sphinx_packet(&packet2, &sks[2]).unwrap();
        match result2 {
            ProcessedPacket::Destination { payload, .. } => {
                assert_eq!(payload, message.to_vec(), "message must be recovered exactly");
            }
            _ => panic!("hop 2 should be destination"),
        }
    }

    #[test]
    fn packet_five_hop_end_to_end() {
        let (route, sks) = make_test_route(5);
        let message = b"five hops of privacy";

        let packet = create_sphinx_packet(message, &route, 1).unwrap();
        let mut current_packet = packet;

        for i in 0..5 {
            let result = process_sphinx_packet(&current_packet, &sks[i]).unwrap();
            if i < 4 {
                match result {
                    ProcessedPacket::Forward { packet, .. } => {
                        current_packet = packet;
                    }
                    _ => panic!("hop {} should forward", i),
                }
            } else {
                match result {
                    ProcessedPacket::Destination { payload, .. } => {
                        assert_eq!(payload, message.to_vec());
                    }
                    _ => panic!("hop {} should be destination", i),
                }
            }
        }
    }

    #[test]
    fn cover_packet_same_size() {
        let (route, _) = make_test_route(3);

        let real = create_sphinx_packet(b"real message", &route, 1).unwrap();
        let cover = create_cover_packet(&route, 1, PacketFlag::DropCover).unwrap();

        assert_eq!(real.to_bytes().len(), cover.to_bytes().len());
        assert_eq!(real.to_bytes().len(), PACKET_SIZE);
    }

    #[test]
    fn packet_payload_too_large() {
        let (route, _) = make_test_route(3);
        let oversized = vec![0xFF; PAYLOAD_SIZE + 1000];
        assert!(create_sphinx_packet(&oversized, &route, 1).is_err());
    }

    #[test]
    fn drop_cover_is_discarded() {
        let (route, sks) = make_test_route(1);
        let cover = create_cover_packet(&route, 1, PacketFlag::DropCover).unwrap();

        match process_sphinx_packet(&cover, &sks[0]).unwrap() {
            ProcessedPacket::DropCover { .. } => {}
            _ => panic!("expected DropCover"),
        }
    }

    #[test]
    fn loop_cover_multi_hop_traversal() {
        let (route, sks) = make_test_route(3);
        let cover = create_cover_packet(&route, 1, PacketFlag::LoopCover).unwrap();

        // Hop 0 forwards
        let p0 = match process_sphinx_packet(&cover, &sks[0]).unwrap() {
            ProcessedPacket::Forward { packet, next_hop, .. } => {
                assert_eq!(next_hop, route[0].routing.next_hop);
                packet
            }
            _ => panic!("hop 0 must forward loop cover packet"),
        };

        // Hop 1 forwards
        let p1 = match process_sphinx_packet(&p0, &sks[1]).unwrap() {
            ProcessedPacket::Forward { packet, next_hop, .. } => {
                assert_eq!(next_hop, route[1].routing.next_hop);
                packet
            }
            _ => panic!("hop 1 must forward loop cover packet"),
        };

        // Hop 2 reaches turnaround / LoopCover destination
        match process_sphinx_packet(&p1, &sks[2]).unwrap() {
            ProcessedPacket::LoopCover { next_hop, packet, .. } => {
                assert_eq!(next_hop, route[2].routing.next_hop);
                assert_eq!(packet.to_bytes().len(), PACKET_SIZE);
            }
            _ => panic!("hop 2 must return ProcessedPacket::LoopCover"),
        }
    }

    #[test]
    fn tampered_packet_detected() {
        let (route, sks) = make_test_route(3);
        let mut packet = create_sphinx_packet(b"tamper test", &route, 1).unwrap();

        // Flip a bit in the routing info
        packet.header.routing_info[5] ^= 0x01;

        let result = process_sphinx_packet(&packet, &sks[0]);
        assert!(result.is_err(), "tampered packet must fail MAC verification");
    }

    #[test]
    fn test_wire_tampering_epoch_id_fails_mac_at_hop1() {
        let (route, sks) = make_test_route(3);
        let packet = create_sphinx_packet(b"hello world", &route, 100).unwrap();
        let mut bytes = packet.to_bytes();

        // Tamper with epoch_id field on wire (bytes 1..5)
        bytes[1] ^= 0x01;

        let tampered_packet = SphinxPacket::from_bytes(&bytes).unwrap();
        let result = process_sphinx_packet(&tampered_packet, &sks[0]);
        assert!(
            matches!(result, Err(SphinxError::MacVerificationFailed { .. })),
            "Wire tampering with epoch_id must trigger MacVerificationFailed at hop 1"
        );
    }

    #[test]
    fn test_wire_tampering_ephemeral_pk_fails_mac_at_hop1() {
        let (route, sks) = make_test_route(3);
        let packet = create_sphinx_packet(b"hello world", &route, 1).unwrap();
        let mut bytes = packet.to_bytes();

        // Tamper with ephemeral public key on wire (bytes 5..37)
        bytes[10] ^= 0xFF;

        let tampered_packet = SphinxPacket::from_bytes(&bytes).unwrap();
        let result = process_sphinx_packet(&tampered_packet, &sks[0]);
        assert!(
            matches!(result, Err(SphinxError::MacVerificationFailed { .. })),
            "Tampering with ephemeral_pk must trigger MacVerificationFailed at hop 1"
        );
    }

    #[test]
    fn test_active_payload_bit_flip_fails_at_destination() {
        let (route, sks) = make_test_route(3);
        let message = b"CRITICAL FINANCIAL TRANSACTION: PAY $10,000";
        let mut packet = create_sphinx_packet(message, &route, 1).unwrap();

        // Active attacker flips a single bit in the ciphertext payload
        packet.payload[250] ^= 0x01;

        // Hop 0 (Forward): strips stream cipher, forwards
        let res0 = process_sphinx_packet(&packet, &sks[0]).unwrap();
        let packet1 = match res0 {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("hop 0 must forward"),
        };

        // Hop 1 (Forward): strips stream cipher, forwards
        let res1 = process_sphinx_packet(&packet1, &sks[1]).unwrap();
        let packet2 = match res1 {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("hop 1 must forward"),
        };

        // Hop 2 (Destination / FinalHop): verifies Poly1305 tag
        let res2 = process_sphinx_packet(&packet2, &sks[2]);
        assert!(
            matches!(res2, Err(SphinxError::PayloadAuthenticationFailed)),
            "Bit flip in payload must trigger PayloadAuthenticationFailed at destination"
        );
    }

    #[test]
    fn test_active_payload_tag_tampering_fails_at_destination() {
        let (route, sks) = make_test_route(3);
        let message = b"Authentication tag integrity test";
        let packet = create_sphinx_packet(message, &route, 1).unwrap();

        // Intermediate hop peels hop 0
        let res0 = process_sphinx_packet(&packet, &sks[0]).unwrap();
        let mut packet1 = match res0 {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("hop 0 must forward"),
        };

        // Attacker tampers with the payload between hop 0 and hop 1
        packet1.payload[PAYLOAD_SIZE - 5] ^= 0x01;

        // Hop 1 peels hop 1
        let res1 = process_sphinx_packet(&packet1, &sks[1]).unwrap();
        let packet2 = match res1 {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("hop 1 must forward"),
        };

        // Hop 2 must reject due to Poly1305 authentication failure
        let res2 = process_sphinx_packet(&packet2, &sks[2]);
        assert!(
            matches!(res2, Err(SphinxError::PayloadAuthenticationFailed)),
            "Tampered tag must trigger PayloadAuthenticationFailed at destination"
        );
    }

    #[test]
    fn test_payload_capacity_boundaries() {
        let (route, sks) = make_test_route(3);
        let max_data = PAYLOAD_PLAINTEXT_SIZE - 4;

        // Max allowed data succeeds
        let max_message = vec![0x42u8; max_data];
        let packet = create_sphinx_packet(&max_message, &route, 1).unwrap();

        let res0 = process_sphinx_packet(&packet, &sks[0]).unwrap();
        let packet1 = match res0 {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("hop 0 must forward"),
        };

        let res1 = process_sphinx_packet(&packet1, &sks[1]).unwrap();
        let packet2 = match res1 {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("hop 1 must forward"),
        };

        let res2 = process_sphinx_packet(&packet2, &sks[2]).unwrap();
        match res2 {
            ProcessedPacket::Destination { payload, .. } => {
                assert_eq!(payload, max_message);
            }
            _ => panic!("hop 2 must be destination"),
        }

        // 1 byte over max fails
        let oversized = vec![0x42u8; max_data + 1];
        assert!(create_sphinx_packet(&oversized, &route, 1).is_err());
    }

    #[test]
    fn packet_from_bytes_strict_size_validation() {
        assert!(SphinxPacket::from_bytes(&[]).is_err());
        assert!(SphinxPacket::from_bytes(&vec![0u8; 100]).is_err());
        assert!(SphinxPacket::from_bytes(&vec![0u8; HEADER_SIZE]).is_err());
        assert!(SphinxPacket::from_bytes(&vec![0u8; HEADER_SIZE + 1]).is_err());
        assert!(SphinxPacket::from_bytes(&vec![0u8; PACKET_SIZE - 1]).is_err());
        assert!(SphinxPacket::from_bytes(&vec![0u8; PACKET_SIZE + 1]).is_err());
    }
}
