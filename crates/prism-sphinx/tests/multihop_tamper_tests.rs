//! Empirical challenger tests for Milestone M1 (Cryptographic Payload & Header Authentication).
//!
//! Adversarial Challenge Focus:
//! 1. Multi-hop routes (3-hop, 5-hop) where wire modification of `epoch_id` is performed:
//!    - before hop 1 (hop 0 in 0-based indexing)
//!    - between hop 1 and hop 2 (intermediate hops)
//!    - between intermediate hops all the way to destination
//! 2. Verification that EVERY hop (hop 1 and all downstream hops) independently detects
//!    and rejects wire modifications of `epoch_id` with `MacVerificationFailed`.
//! 3. Downstream protection: even if a malicious relay forwards a packet with a modified `epoch_id`,
//!    the downstream relay's MAC verification independently rejects it.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use rand::rngs::StdRng;
use rand::SeedableRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use prism_sphinx::errors::SphinxError;
use prism_sphinx::packet::{
    create_sphinx_packet, process_sphinx_packet, ProcessedPacket, SphinxPacket,
};
use prism_sphinx::routing::{PacketFlag, RouteHop, RoutingInfo};

/// Helper to generate a multi-hop route with `num_hops` relays.
fn make_test_route(num_hops: usize, seed: u64) -> (Vec<RouteHop>, Vec<[u8; 32]>) {
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

// ============================================================================
// 1. 3-HOP MULTI-HOP WIRE MODIFICATION OF EPOCH_ID
// ============================================================================

#[test]
fn test_3hop_epoch_id_wire_tamper_before_hop1() {
    let (route, sks) = make_test_route(3, 10001);
    let original_epoch = 42u32;
    let message = b"3-hop tamper before hop 1";
    let packet = create_sphinx_packet(message, &route, original_epoch).unwrap();

    let mut rejections = 0;
    let mut tested = 0;

    // Tamper all 4 bytes of epoch_id on the wire (bytes 1..=4)
    for byte_offset in 1..=4 {
        for bit in 0..8 {
            let mut wire_bytes = packet.to_bytes();
            wire_bytes[byte_offset] ^= 1 << bit;

            tested += 1;
            let tampered_packet = SphinxPacket::from_bytes(&wire_bytes).unwrap();
            let res = process_sphinx_packet(&tampered_packet, &sks[0]);

            assert!(
                matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
                "Hop 1 MUST reject wire-tampered epoch_id at byte {} bit {} with MacVerificationFailed",
                byte_offset, bit
            );
            rejections += 1;
        }
    }

    // Also test gross values: 0, u32::MAX, adjacent values
    let gross_epochs = [0u32, 1, 41, 43, 100, 0xFFFF_FFFF];
    for &fake_epoch in &gross_epochs {
        if fake_epoch == original_epoch {
            continue;
        }
        let mut wire_bytes = packet.to_bytes();
        wire_bytes[1..5].copy_from_slice(&fake_epoch.to_be_bytes());

        tested += 1;
        let tampered_packet = SphinxPacket::from_bytes(&wire_bytes).unwrap();
        let res = process_sphinx_packet(&tampered_packet, &sks[0]);

        assert!(
            matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
            "Hop 1 MUST reject gross epoch replacement {} with MacVerificationFailed",
            fake_epoch
        );
        rejections += 1;
    }

    assert_eq!(rejections, tested);
    assert_eq!(rejections, 32 + gross_epochs.len());
}

#[test]
fn test_3hop_epoch_id_wire_tamper_between_hop1_and_hop2() {
    let (route, sks) = make_test_route(3, 10002);
    let original_epoch = 12345u32;
    let message = b"3-hop tamper between hop 1 and hop 2";
    let packet = create_sphinx_packet(message, &route, original_epoch).unwrap();

    // Hop 1 processes valid packet and outputs packet for Hop 2
    let p1 = match process_sphinx_packet(&packet, &sks[0]).unwrap() {
        ProcessedPacket::Forward { packet, .. } => packet,
        _ => panic!("hop 1 forward expected"),
    };

    let mut rejections = 0;
    let mut tested = 0;

    // Tamper the wire between Hop 1 and Hop 2 across all 32 bits of epoch_id
    for byte_offset in 1..=4 {
        for bit in 0..8 {
            let mut wire_bytes = p1.to_bytes();
            wire_bytes[byte_offset] ^= 1 << bit;

            tested += 1;
            let tampered_p1 = SphinxPacket::from_bytes(&wire_bytes).unwrap();
            let res = process_sphinx_packet(&tampered_p1, &sks[1]);

            assert!(
                matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
                "Hop 2 MUST reject wire-tampered epoch_id at byte {} bit {} with MacVerificationFailed",
                byte_offset, bit
            );
            rejections += 1;
        }
    }

    assert_eq!(rejections, tested);
    assert_eq!(rejections, 32);
}

#[test]
fn test_3hop_epoch_id_wire_tamper_between_hop2_and_hop3() {
    let (route, sks) = make_test_route(3, 10003);
    let original_epoch = 999u32;
    let message = b"3-hop tamper between hop 2 and hop 3";
    let packet = create_sphinx_packet(message, &route, original_epoch).unwrap();

    // Hop 1 processes
    let p1 = match process_sphinx_packet(&packet, &sks[0]).unwrap() {
        ProcessedPacket::Forward { packet, .. } => packet,
        _ => panic!("hop 1 forward expected"),
    };

    // Hop 2 processes
    let p2 = match process_sphinx_packet(&p1, &sks[1]).unwrap() {
        ProcessedPacket::Forward { packet, .. } => packet,
        _ => panic!("hop 2 forward expected"),
    };

    let mut rejections = 0;
    let mut tested = 0;

    // Tamper the wire between Hop 2 and Hop 3 (final destination) across all 32 bits of epoch_id
    for byte_offset in 1..=4 {
        for bit in 0..8 {
            let mut wire_bytes = p2.to_bytes();
            wire_bytes[byte_offset] ^= 1 << bit;

            tested += 1;
            let tampered_p2 = SphinxPacket::from_bytes(&wire_bytes).unwrap();
            let res = process_sphinx_packet(&tampered_p2, &sks[2]);

            assert!(
                matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
                "Hop 3 (destination) MUST reject wire-tampered epoch_id at byte {} bit {} with MacVerificationFailed",
                byte_offset, bit
            );
            rejections += 1;
        }
    }

    assert_eq!(rejections, tested);
    assert_eq!(rejections, 32);
}

// ============================================================================
// 2. 5-HOP MULTI-HOP WIRE MODIFICATION OF EPOCH_ID
// ============================================================================

#[test]
fn test_5hop_epoch_id_wire_tamper_at_each_hop() {
    let (route, sks) = make_test_route(5, 20001);
    let original_epoch = 777u32;
    let message = b"5-hop full circuit tamper test";
    let packet = create_sphinx_packet(message, &route, original_epoch).unwrap();

    // Test tamper before Hop 1 (relay 0)
    {
        let mut wire_bytes = packet.to_bytes();
        wire_bytes[1] ^= 0x01; // flip bit in epoch_id
        let tampered = SphinxPacket::from_bytes(&wire_bytes).unwrap();
        let res = process_sphinx_packet(&tampered, &sks[0]);
        assert!(
            matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
            "Hop 1 must reject tampered epoch_id"
        );
    }

    // Hop 1 processes untampered packet
    let p1 = match process_sphinx_packet(&packet, &sks[0]).unwrap() {
        ProcessedPacket::Forward { packet, .. } => packet,
        _ => panic!("hop 1 forward expected"),
    };

    // Test tamper between Hop 1 and Hop 2 (relay 1)
    {
        let mut wire_bytes = p1.to_bytes();
        wire_bytes[2] ^= 0x02; // flip bit in epoch_id
        let tampered = SphinxPacket::from_bytes(&wire_bytes).unwrap();
        let res = process_sphinx_packet(&tampered, &sks[1]);
        assert!(
            matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
            "Hop 2 must reject tampered epoch_id"
        );
    }

    // Hop 2 processes untampered p1
    let p2 = match process_sphinx_packet(&p1, &sks[1]).unwrap() {
        ProcessedPacket::Forward { packet, .. } => packet,
        _ => panic!("hop 2 forward expected"),
    };

    // Test tamper between Hop 2 and Hop 3 (relay 2)
    {
        let mut wire_bytes = p2.to_bytes();
        wire_bytes[3] ^= 0x04; // flip bit in epoch_id
        let tampered = SphinxPacket::from_bytes(&wire_bytes).unwrap();
        let res = process_sphinx_packet(&tampered, &sks[2]);
        assert!(
            matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
            "Hop 3 must reject tampered epoch_id"
        );
    }

    // Hop 3 processes untampered p2
    let p3 = match process_sphinx_packet(&p2, &sks[2]).unwrap() {
        ProcessedPacket::Forward { packet, .. } => packet,
        _ => panic!("hop 3 forward expected"),
    };

    // Test tamper between Hop 3 and Hop 4 (relay 3)
    {
        let mut wire_bytes = p3.to_bytes();
        wire_bytes[4] ^= 0x08; // flip bit in epoch_id
        let tampered = SphinxPacket::from_bytes(&wire_bytes).unwrap();
        let res = process_sphinx_packet(&tampered, &sks[3]);
        assert!(
            matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
            "Hop 4 must reject tampered epoch_id"
        );
    }

    // Hop 4 processes untampered p3
    let p4 = match process_sphinx_packet(&p3, &sks[3]).unwrap() {
        ProcessedPacket::Forward { packet, .. } => packet,
        _ => panic!("hop 4 forward expected"),
    };

    // Test tamper between Hop 4 and Hop 5 (relay 4 / destination)
    {
        let mut wire_bytes = p4.to_bytes();
        wire_bytes[1] ^= 0x80; // flip bit in epoch_id
        let tampered = SphinxPacket::from_bytes(&wire_bytes).unwrap();
        let res = process_sphinx_packet(&tampered, &sks[4]);
        assert!(
            matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
            "Hop 5 (destination) must reject tampered epoch_id"
        );
    }

    // Finally, Hop 5 processes untampered p4 and verifies payload integrity
    let dest_res = process_sphinx_packet(&p4, &sks[4]).unwrap();
    match dest_res {
        ProcessedPacket::Destination { payload, .. } => {
            assert_eq!(payload, message);
        }
        _ => panic!("hop 5 destination expected"),
    }
}

// ============================================================================
// 3. MALICIOUS RELAY DOWNSTREAM EPOCH FORGERY PROTECTION
// ============================================================================

#[test]
fn test_malicious_relay_forwarding_altered_epoch_id() {
    let (route, sks) = make_test_route(3, 30001);
    let original_epoch = 50u32;
    let packet = create_sphinx_packet(b"adversarial relay test", &route, original_epoch).unwrap();

    // Normal processing at Hop 1 produces `p1`
    let p1 = match process_sphinx_packet(&packet, &sks[0]).unwrap() {
        ProcessedPacket::Forward { packet, .. } => packet,
        _ => panic!("hop 1 forward expected"),
    };

    // Scenario: A malicious relay at Hop 1 tampers with `epoch_id` in the forwarded header
    // from 50 to 51 (hoping to confuse Hop 2 into an invalid state or exploit replay)
    let mut malicious_p1 = p1.clone();
    malicious_p1.header.epoch_id = 51;

    let res = process_sphinx_packet(&malicious_p1, &sks[1]);
    assert!(
        matches!(res, Err(SphinxError::MacVerificationFailed { .. })),
        "Hop 2 MUST reject forwarded packet with forged epoch_id"
    );
}

// ============================================================================
// 4. CONTROL: UNTAMPERED MULTI-HOP CIRCUITS DELIVER WITH 100% FIDELITY
// ============================================================================

#[test]
fn test_untampered_3hop_and_5hop_fidelity() {
    // 3-hop
    {
        let (route, sks) = make_test_route(3, 40003);
        let msg = b"Valid 3-hop message";
        let packet = create_sphinx_packet(msg, &route, 10).unwrap();
        let p1 = match process_sphinx_packet(&packet, &sks[0]).unwrap() {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("expected forward"),
        };
        let p2 = match process_sphinx_packet(&p1, &sks[1]).unwrap() {
            ProcessedPacket::Forward { packet, .. } => packet,
            _ => panic!("expected forward"),
        };
        match process_sphinx_packet(&p2, &sks[2]).unwrap() {
            ProcessedPacket::Destination { payload, .. } => assert_eq!(payload, msg),
            _ => panic!("expected destination"),
        }
    }

    // 5-hop
    {
        let (route, sks) = make_test_route(5, 40005);
        let msg = b"Valid 5-hop message through entire network";
        let packet = create_sphinx_packet(msg, &route, 20).unwrap();
        let mut cur_p = packet;
        for i in 0..4 {
            cur_p = match process_sphinx_packet(&cur_p, &sks[i]).unwrap() {
                ProcessedPacket::Forward { packet, .. } => packet,
                _ => panic!("expected forward at hop {}", i),
            };
        }
        match process_sphinx_packet(&cur_p, &sks[4]).unwrap() {
            ProcessedPacket::Destination { payload, .. } => assert_eq!(payload, msg),
            _ => panic!("expected destination at hop 4"),
        }
    }
}
