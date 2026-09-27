//! Adversarial challenge test suite for Milestone M1 (Cryptographic Payload & Header Authentication).
//!
//! Evaluates:
//! 1. Payload bit-flipping across multiple offsets (first byte, middle byte, padding region, tag bytes, randomized).
//! 2. Header byte tampering across header offsets (version, epoch_id, ephemeral_pk, routing_info, mac).
//! 3. Malformed packets, truncated buffers, empty messages, maximum size messages (31,684 bytes), and oversize messages.
//! 4. 100% fidelity verification for legitimate packets across 1..=5 hops and various payload sizes.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use prism_sphinx::constants::*;
use prism_sphinx::errors::SphinxError;
use prism_sphinx::packet::{
    create_cover_packet, create_sphinx_packet, process_sphinx_packet,
    ProcessedPacket, SphinxPacket,
};
use prism_sphinx::routing::{PacketFlag, RouteHop, RoutingInfo};

/// Helper to generate a route with `num_hops` relays.
fn make_adversarial_route(num_hops: usize, seed: u64) -> (Vec<RouteHop>, Vec<[u8; 32]>) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut hops = Vec::with_capacity(num_hops);
    let mut secret_keys = Vec::with_capacity(num_hops);

    for i in 0..num_hops {
        let sk = X25519Secret::random_from_rng(&mut rng);
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

/// Helper to route a packet through intermediate relays up to destination or error.
fn route_packet_to_destination(
    mut packet: SphinxPacket,
    sks: &[[u8; 32]],
) -> Result<Vec<u8>, SphinxError> {
    for (i, sk) in sks.iter().enumerate() {
        match process_sphinx_packet(&packet, sk)? {
            ProcessedPacket::Forward { packet: next_p, .. } => {
                packet = next_p;
            }
            ProcessedPacket::Destination { payload, .. } => {
                if i != sks.len() - 1 {
                    panic!("Premature destination at hop {} of {}", i, sks.len());
                }
                return Ok(payload);
            }
            ProcessedPacket::LoopCover { .. } | ProcessedPacket::DropCover { .. } => {
                panic!("Unexpected cover packet flag at hop {}", i);
            }
        }
    }
    panic!("Route exhausted without reaching destination or failing");
}

// ============================================================================
// 1. ADVERSARIAL PAYLOAD TAMPERING TESTS
// ============================================================================

#[test]
fn test_adversarial_payload_bitflip_first_byte() {
    let (route, sks) = make_adversarial_route(3, 1001);
    let message = b"Adversarial payload tamper test: first byte";
    let mut packet = create_sphinx_packet(message, &route, 1).unwrap();

    // Flip bit 0 of the first payload byte (offset 0)
    packet.payload[0] ^= 0x01;

    let res = route_packet_to_destination(packet, &sks);
    assert!(
        matches!(res, Err(SphinxError::PayloadAuthenticationFailed)),
        "Bit-flip at offset 0 must be rejected with PayloadAuthenticationFailed"
    );
}

#[test]
fn test_adversarial_payload_bitflip_middle_byte() {
    let (route, sks) = make_adversarial_route(3, 1002);
    let message = b"Adversarial payload tamper test: middle byte";
    let mut packet = create_sphinx_packet(message, &route, 1).unwrap();

    // Middle byte of 31,744 bytes
    let middle_offset = PAYLOAD_SIZE / 2;
    packet.payload[middle_offset] ^= 0x80;

    let res = route_packet_to_destination(packet, &sks);
    assert!(
        matches!(res, Err(SphinxError::PayloadAuthenticationFailed)),
        "Bit-flip at middle offset {} must trigger PayloadAuthenticationFailed",
        middle_offset
    );
}

#[test]
fn test_adversarial_payload_bitflip_padding_region() {
    let (route, sks) = make_adversarial_route(3, 1003);
    let message = b"Short message with padding";
    let mut packet = create_sphinx_packet(message, &route, 1).unwrap();

    // Tamper deep in the padding area (e.g. byte 5000, where original was 0x00 padding)
    let pad_offset = 5000;
    packet.payload[pad_offset] ^= 0x04;

    let res = route_packet_to_destination(packet, &sks);
    assert!(
        matches!(res, Err(SphinxError::PayloadAuthenticationFailed)),
        "Bit-flip in padding region at offset {} must trigger PayloadAuthenticationFailed",
        pad_offset
    );
}

#[test]
fn test_adversarial_payload_bitflip_tag_bytes_exhaustive() {
    let (route, sks) = make_adversarial_route(3, 1004);
    let message = b"Testing all 16 bytes of the Poly1305 authentication tag";

    // Test each byte of the tag (last 16 bytes: PAYLOAD_SIZE - 16 .. PAYLOAD_SIZE)
    let tag_start = PAYLOAD_SIZE - PAYLOAD_TAG_SIZE;
    let mut total_tests = 0;
    let mut rejections = 0;

    for byte_offset in tag_start..PAYLOAD_SIZE {
        for bit in 0..8 {
            let mut packet = create_sphinx_packet(message, &route, 1).unwrap();
            packet.payload[byte_offset] ^= 1 << bit;

            total_tests += 1;
            let res = route_packet_to_destination(packet, &sks);
            if matches!(res, Err(SphinxError::PayloadAuthenticationFailed)) {
                rejections += 1;
            }
        }
    }

    assert_eq!(total_tests, 16 * 8, "Expected 128 bit-flip tests on tag");
    assert_eq!(
        rejections, total_tests,
        "100% rejection required for tag bit-flips: got {}/{}",
        rejections, total_tests
    );
}

#[test]
fn test_adversarial_payload_random_bitflips_sweep() {
    let (route, sks) = make_adversarial_route(3, 1005);
    let message = b"Payload random bitflips sweep across entire 31,744 bytes";
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);

    let sweep_count = 500;
    let mut rejections = 0;

    for _ in 0..sweep_count {
        let mut packet = create_sphinx_packet(message, &route, 1).unwrap();
        let random_offset = rng.gen_range(0..PAYLOAD_SIZE);
        let bit = rng.gen_range(0..8);
        packet.payload[random_offset] ^= 1 << bit;

        let res = route_packet_to_destination(packet, &sks);
        if matches!(res, Err(SphinxError::PayloadAuthenticationFailed)) {
            rejections += 1;
        }
    }

    assert_eq!(
        rejections, sweep_count,
        "100% rejection required: {}/{} rejected",
        rejections, sweep_count
    );
}

#[test]
fn test_adversarial_payload_tampering_at_each_wire_hop() {
    let (route, sks) = make_adversarial_route(3, 1006);
    let message = b"Wire hop tampering test";

    // Scenario A: Tampering between client and Hop 0
    {
        let mut packet = create_sphinx_packet(message, &route, 1).unwrap();
        packet.payload[42] ^= 0xAA;

        // Hop 0 peels layer (does not detect — by design)
        let p0 = match process_sphinx_packet(&packet, &sks[0]).unwrap() {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("hop 0 forward expected"),
        };
        // Hop 1 peels layer
        let p1 = match process_sphinx_packet(&p0, &sks[1]).unwrap() {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("hop 1 forward expected"),
        };
        // Hop 2 (destination) verifies AEAD
        let res = process_sphinx_packet(&p1, &sks[2]);
        assert!(
            matches!(res, Err(SphinxError::PayloadAuthenticationFailed)),
            "Hop 0 wire tamper must fail at destination"
        );
    }

    // Scenario B: Tampering between Hop 0 and Hop 1
    {
        let packet = create_sphinx_packet(message, &route, 1).unwrap();
        let mut p0 = match process_sphinx_packet(&packet, &sks[0]).unwrap() {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("hop 0 forward expected"),
        };
        p0.payload[1234] ^= 0x55;

        let p1 = match process_sphinx_packet(&p0, &sks[1]).unwrap() {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("hop 1 forward expected"),
        };
        let res = process_sphinx_packet(&p1, &sks[2]);
        assert!(
            matches!(res, Err(SphinxError::PayloadAuthenticationFailed)),
            "Hop 1 wire tamper must fail at destination"
        );
    }

    // Scenario C: Tampering between Hop 1 and Hop 2 (FinalHop)
    {
        let packet = create_sphinx_packet(message, &route, 1).unwrap();
        let p0 = match process_sphinx_packet(&packet, &sks[0]).unwrap() {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("hop 0 forward expected"),
        };
        let mut p1 = match process_sphinx_packet(&p0, &sks[1]).unwrap() {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("hop 1 forward expected"),
        };
        p1.payload[30000] ^= 0x01;

        let res = process_sphinx_packet(&p1, &sks[2]);
        assert!(
            matches!(res, Err(SphinxError::PayloadAuthenticationFailed)),
            "Hop 2 wire tamper must fail at destination"
        );
    }
}

// ============================================================================
// 2. ADVERSARIAL HEADER TAMPERING TESTS
// ============================================================================

#[test]
fn test_adversarial_header_version_tampering() {
    let (route, sks) = make_adversarial_route(3, 2001);
    let packet = create_sphinx_packet(b"version tamper test", &route, 1).unwrap();

    let mut rejections = 0;
    let mut tested = 0;

    for v in 0..=255u8 {
        if v == PROTOCOL_VERSION {
            continue;
        }
        let mut bytes = packet.to_bytes();
        bytes[0] = v; // version is at offset 0

        tested += 1;
        match SphinxPacket::from_bytes(&bytes) {
            Err(SphinxError::UnsupportedVersion(_)) => {
                rejections += 1;
            }
            Ok(tampered_p) => {
                // If deserialization succeeded, MAC verification must fail
                let res = process_sphinx_packet(&tampered_p, &sks[0]);
                if matches!(res, Err(SphinxError::MacVerificationFailed { .. })) {
                    rejections += 1;
                }
            }
            Err(_) => {
                rejections += 1;
            }
        }
    }

    assert_eq!(rejections, tested, "All 255 invalid versions must be rejected: {}/{}", rejections, tested);
}

#[test]
fn test_adversarial_header_epoch_id_tampering() {
    let (route, sks) = make_adversarial_route(3, 2002);
    let epoch_id = 0x12345678u32;
    let packet = create_sphinx_packet(b"epoch tamper test", &route, epoch_id).unwrap();

    // Tamper each of the 4 epoch bytes (offsets 1..5) in wire format
    let mut rejections = 0;
    let mut tested = 0;

    for offset in 1..=4 {
        for bit in 0..8 {
            let mut bytes = packet.to_bytes();
            bytes[offset] ^= 1 << bit;

            tested += 1;
            let tampered_packet = SphinxPacket::from_bytes(&bytes).unwrap();
            let res = process_sphinx_packet(&tampered_packet, &sks[0]);
            assert!(
                matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
                "Tampered epoch_id at byte {} bit {} did not fail MAC",
                offset,
                bit
            );
            rejections += 1;
        }
    }

    assert_eq!(rejections, tested);
    assert_eq!(rejections, 32, "All 32 epoch_id bit-flips must fail MAC");
}

#[test]
fn test_adversarial_header_ephemeral_pk_tampering() {
    let (route, sks) = make_adversarial_route(3, 2003);
    let packet = create_sphinx_packet(b"ephemeral pk tamper test", &route, 1).unwrap();

    // Ephemeral PK is at bytes 5..37 (32 bytes)
    let mut rejections = 0;
    let mut tested = 0;

    for offset in 5..37 {
        for bit in [0, 3, 7] {
            let mut bytes = packet.to_bytes();
            bytes[offset] ^= 1 << bit;

            tested += 1;
            let tampered_packet = SphinxPacket::from_bytes(&bytes).unwrap();
            let res = process_sphinx_packet(&tampered_packet, &sks[0]);
            assert!(
                matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
                "Tampered ephemeral pk at byte {} bit {} did not fail MAC",
                offset,
                bit
            );
            rejections += 1;
        }
    }

    assert_eq!(rejections, tested);
    assert_eq!(rejections, 32 * 3);
}

#[test]
fn test_adversarial_header_routing_info_tampering() {
    let (route, sks) = make_adversarial_route(3, 2004);
    let packet = create_sphinx_packet(b"routing info tamper test", &route, 1).unwrap();

    // Routing info is at bytes 37..317 (280 bytes)
    let offsets_to_test = [
        37,                     // first byte of routing info (hop 0 block)
        37 + 23,                // end of hop 0 routing data
        37 + 24,                // hop 0 embedded next MAC
        37 + ROUTING_BLOCK_SIZE - 1, // end of hop 0 block
        37 + ROUTING_BLOCK_SIZE, // start of hop 1 block
        37 + 2 * ROUTING_BLOCK_SIZE, // start of hop 2 block
        316,                    // last byte of routing info
    ];

    let mut rejections = 0;

    for &offset in &offsets_to_test {
        let mut bytes = packet.to_bytes();
        bytes[offset] ^= 0x01;

        let tampered_packet = SphinxPacket::from_bytes(&bytes).unwrap();
        let res = process_sphinx_packet(&tampered_packet, &sks[0]);
        assert!(
            matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
            "Tampered routing info at offset {} did not fail MAC",
            offset
        );
        rejections += 1;
    }

    assert_eq!(rejections, offsets_to_test.len());
}

#[test]
fn test_adversarial_header_mac_tampering() {
    let (route, sks) = make_adversarial_route(3, 2005);
    let packet = create_sphinx_packet(b"mac tamper test", &route, 1).unwrap();

    // MAC is at bytes 317..349 (32 bytes)
    let mac_start = 37 + ROUTING_INFO_SIZE;
    assert_eq!(mac_start, 317);

    let mut rejections = 0;
    let mut tested = 0;

    for offset in mac_start..mac_start + MAC_SIZE {
        for bit in [0, 4, 7] {
            let mut bytes = packet.to_bytes();
            bytes[offset] ^= 1 << bit;

            tested += 1;
            let tampered_packet = SphinxPacket::from_bytes(&bytes).unwrap();
            let res = process_sphinx_packet(&tampered_packet, &sks[0]);
            assert!(
                matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
                "Tampered MAC at offset {} bit {} did not fail MAC",
                offset,
                bit
            );
            rejections += 1;
        }
    }

    assert_eq!(rejections, tested);
    assert_eq!(rejections, 32 * 3);
}

#[test]
fn test_adversarial_header_exhaustive_sweep() {
    let (route, sks) = make_adversarial_route(3, 2006);
    let packet = create_sphinx_packet(b"exhaustive header sweep", &route, 1).unwrap();

    // Sweep all 349 bytes of the authenticated header structure (version..mac end)
    let mut rejections = 0;
    let total_bytes = 1 + 4 + 32 + ROUTING_INFO_SIZE + MAC_SIZE; // 349 bytes
    assert_eq!(total_bytes, 349);

    for offset in 0..total_bytes {
        let mut bytes = packet.to_bytes();
        bytes[offset] ^= 0x01;

        match SphinxPacket::from_bytes(&bytes) {
            Ok(tampered) => {
                let res = process_sphinx_packet(&tampered, &sks[0]);
                if matches!(res, Err(SphinxError::MacVerificationFailed { .. }))
                    || (offset == 0 && matches!(res, Err(SphinxError::UnsupportedVersion(_))))
                {
                    rejections += 1;
                } else {
                    panic!("Tampering at offset {} bypassed MAC", offset);
                }
            }
            Err(SphinxError::UnsupportedVersion(_)) if offset == 0 => {
                rejections += 1;
            }
            Err(e) => {
                panic!("Unexpected deserialization failure at offset {}: {:?}", offset, e);
            }
        }
    }

    assert_eq!(rejections, 349, "100% rejection required across all 349 header bytes");
}

// ============================================================================
// 3. MALFORMED, TRUNCATED, EMPTY, AND BOUNDARY PACKET TESTS
// ============================================================================

#[test]
fn test_adversarial_truncated_packets() {
    let truncated_lengths = [0, 1, 10, 100, 500, HEADER_SIZE - 1, HEADER_SIZE, PACKET_SIZE - 1];

    for &len in &truncated_lengths {
        let fake_data = vec![0x42u8; len];
        let res = SphinxPacket::from_bytes(&fake_data);
        assert!(
            res.is_err(),
            "Packet of length {} should be rejected by from_bytes",
            len
        );
    }
}

#[test]
fn test_adversarial_empty_message() {
    let (route, sks) = make_adversarial_route(3, 3001);
    let empty_msg = b"";

    let packet = create_sphinx_packet(empty_msg, &route, 1).unwrap();
    assert_eq!(packet.to_bytes().len(), PACKET_SIZE);

    let recovered = route_packet_to_destination(packet, &sks).unwrap();
    assert_eq!(recovered, empty_msg.to_vec(), "Empty message must roundtrip with 100% fidelity");
}

#[test]
fn test_adversarial_max_payload_data_31684_bytes() {
    let (route, sks) = make_adversarial_route(3, 3002);
    // Exact MAX_PAYLOAD_DATA size: 31,684 bytes
    assert_eq!(MAX_PAYLOAD_DATA, 31684);

    let mut max_msg = vec![0u8; MAX_PAYLOAD_DATA];
    for (i, b) in max_msg.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let packet = create_sphinx_packet(&max_msg, &route, 1).unwrap();
    assert_eq!(packet.to_bytes().len(), PACKET_SIZE);

    let recovered = route_packet_to_destination(packet, &sks).unwrap();
    assert_eq!(recovered.len(), MAX_PAYLOAD_DATA);
    assert_eq!(recovered, max_msg, "MAX_PAYLOAD_DATA (31,684 B) must decrypt with 100% fidelity");
}

#[test]
fn test_adversarial_max_unfragmented_capacity_31724_bytes() {
    let (route, sks) = make_adversarial_route(3, 3003);
    // PAYLOAD_PLAINTEXT_SIZE - 4 = 31,724 bytes
    let max_unfragmented = PAYLOAD_PLAINTEXT_SIZE - 4;
    assert_eq!(max_unfragmented, 31724);

    let mut max_msg = vec![0u8; max_unfragmented];
    for (i, b) in max_msg.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }

    let packet = create_sphinx_packet(&max_msg, &route, 1).unwrap();
    let recovered = route_packet_to_destination(packet, &sks).unwrap();
    assert_eq!(recovered, max_msg, "31,724 bytes must decrypt with 100% fidelity");
}

#[test]
fn test_adversarial_oversize_messages_rejected() {
    let (route, _) = make_adversarial_route(3, 3004);
    let max_unfragmented = PAYLOAD_PLAINTEXT_SIZE - 4; // 31,724

    // 1 byte over max unfragmented capacity
    let over_by_1 = vec![0xEEu8; max_unfragmented + 1];
    let res1 = create_sphinx_packet(&over_by_1, &route, 1);
    assert!(
        matches!(res1, Err(SphinxError::PayloadTooLarge { max: 31724, got: 31725 })),
        "31,725 byte message must return PayloadTooLarge"
    );

    // Large oversize
    let way_over = vec![0xEEu8; 64_000];
    let res2 = create_sphinx_packet(&way_over, &route, 1);
    assert!(matches!(res2, Err(SphinxError::PayloadTooLarge { .. })));
}

// ============================================================================
// 4. LEGITIMATE PACKET FIDELITY TESTS (100% INTEGRITY)
// ============================================================================

#[test]
fn test_legitimate_fidelity_across_hop_counts() {
    let payload_sizes = [0, 1, 17, 128, 1024, 8192, 16384, 31684, 31724];

    for num_hops in 1..=MAX_HOPS {
        let (route, sks) = make_adversarial_route(num_hops, 4000 + num_hops as u64);

        for &size in &payload_sizes {
            let mut msg = vec![0u8; size];
            for (idx, b) in msg.iter_mut().enumerate() {
                *b = ((idx * 7 + num_hops * 13) % 256) as u8;
            }

            let packet = create_sphinx_packet(&msg, &route, num_hops as u32)
                .unwrap_or_else(|e| panic!("Failed to create packet: num_hops={}, size={}, err={:?}", num_hops, size, e));

            assert_eq!(packet.to_bytes().len(), PACKET_SIZE);

            let recovered = route_packet_to_destination(packet, &sks)
                .unwrap_or_else(|e| panic!("Failed to route packet: num_hops={}, size={}, err={:?}", num_hops, size, e));

            assert_eq!(
                recovered, msg,
                "Fidelity mismatch for num_hops={}, size={}",
                num_hops, size
            );
        }
    }
}

#[test]
fn test_legitimate_cover_traffic_fidelity() {
    let (route, sks) = make_adversarial_route(3, 5001);

    // DropCover packet
    let drop_cover = create_cover_packet(&route, 1, PacketFlag::DropCover).unwrap();
    assert_eq!(drop_cover.to_bytes().len(), PACKET_SIZE);

    let p0 = match process_sphinx_packet(&drop_cover, &sks[0]).unwrap() {
        ProcessedPacket::Forward { packet, .. } => packet,
        _ => panic!("hop 0 forward expected"),
    };
    let p1 = match process_sphinx_packet(&p0, &sks[1]).unwrap() {
        ProcessedPacket::Forward { packet, .. } => packet,
        _ => panic!("hop 1 forward expected"),
    };
    match process_sphinx_packet(&p1, &sks[2]).unwrap() {
        ProcessedPacket::DropCover { .. } => {}
        _ => panic!("hop 2 DropCover expected"),
    }
}
