use std::time::Instant;
use crate::stats::BenchStats;
use prism_sphinx::{
    constants::{PACKET_SIZE, PAYLOAD_SIZE},
    header::{build_header, process_header},
    packet::{create_sphinx_packet, process_sphinx_packet, SphinxPacket},
    payload::{decrypt_payload_layer, encrypt_payload_all_layers, pad_payload, unpad_payload},
    replay::ReplayFilter,
    routing::{PacketFlag, RouteHop, RoutingInfo},
};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

pub fn make_mock_route(num_hops: usize) -> (Vec<RouteHop>, Vec<[u8; 32]>) {
    let mut hops = Vec::with_capacity(num_hops);
    let mut secrets = Vec::with_capacity(num_hops);
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
                next_hop: format!("127.0.0.1:{}", 9001 + i).parse().unwrap(),
                delay_seed: i as u32,
                flag,
                reserved: 0,
            },
            public_key: pk.to_bytes(),
        });
        secrets.push(sk.to_bytes());
    }
    (hops, secrets)
}

pub fn run_sphinx_benchmarks(iters: usize) -> Vec<BenchStats> {
    let mut results = Vec::new();

    // 1. Header Construction: 1, 3, 5 hops
    for hops in [1, 3, 5] {
        let (route, _) = make_mock_route(hops);
        let mut samples = Vec::with_capacity(iters);
        for _ in 0..iters {
            let start = Instant::now();
            let _ = build_header(&route, 1).unwrap();
            samples.push(start.elapsed().as_nanos() as u64);
        }
        results.push(BenchStats::compute(
            &format!("Sphinx Header Build ({} hops)", hops),
            samples,
            None,
        ));
    }

    // 2. Header Processing at Relay
    let (route, sks) = make_mock_route(3);
    let (header, _) = build_header(&route, 1).unwrap();
    let relay_sk = sks[0];
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = process_header(&header, &relay_sk).unwrap();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Sphinx Header Process (Relay)", samples, None));

    // 3. Payload Padding & Unpadding
    let raw_msg_1k = vec![0x42u8; 1024];
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = pad_payload(&raw_msg_1k, PAYLOAD_SIZE).unwrap();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Payload Pad (1KB -> 31.7KB)", samples, Some(PAYLOAD_SIZE)));

    let padded = pad_payload(&raw_msg_1k, PAYLOAD_SIZE).unwrap();
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = unpad_payload(&padded).unwrap();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Payload Unpad", samples, Some(PAYLOAD_SIZE)));

    // 4. Layered Payload Encryption (1, 3, 5 hops)
    for hops in [1, 3, 5] {
        let (_, client_secrets) = make_mock_route(hops);
        let mut samples = Vec::with_capacity(iters);
        for _ in 0..iters {
            let mut payload_buf = padded.clone();
            let start = Instant::now();
            encrypt_payload_all_layers(&client_secrets, &mut payload_buf);
            samples.push(start.elapsed().as_nanos() as u64);
        }
        results.push(BenchStats::compute(
            &format!("Payload Layered Encrypt ({} hops, 31.7KB)", hops),
            samples,
            Some(PAYLOAD_SIZE * hops),
        ));
    }

    // 5. Payload Single Layer Decrypt
    let mut payload_buf = padded.clone();
    let secret = [0x55u8; 32];
    encrypt_payload_all_layers(&[secret], &mut payload_buf);
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let mut dec_buf = payload_buf.clone();
        let start = Instant::now();
        decrypt_payload_layer(&secret, &mut dec_buf);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute(
        "Payload Single Layer Decrypt (31.7KB)",
        samples,
        Some(PAYLOAD_SIZE),
    ));

    // 6. Full Packet Creation: across message sizes
    let (route_3, sks_3) = make_mock_route(3);
    for msg_size in [64, 1024, 16384, 31000] {
        let msg = vec![0x7Au8; msg_size];
        let mut samples = Vec::with_capacity(iters);
        for _ in 0..iters {
            let start = Instant::now();
            let _ = create_sphinx_packet(&msg, &route_3, 1).unwrap();
            samples.push(start.elapsed().as_nanos() as u64);
        }
        results.push(BenchStats::compute(
            &format!("Full Packet Create (3 hops, {}B msg)", msg_size),
            samples,
            Some(PACKET_SIZE),
        ));
    }

    // 7. Full Packet Relay Processing: Intermediate Hop vs Final Hop
    let test_packet = create_sphinx_packet(&raw_msg_1k, &route_3, 1).unwrap();
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = process_sphinx_packet(&test_packet, &sks_3[0]).unwrap();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute(
        "Sphinx Packet Relay Process (Hop 1/Forward)",
        samples,
        Some(PACKET_SIZE),
    ));

    // Reach hop 3 (FinalHop)
    let processed1 = process_sphinx_packet(&test_packet, &sks_3[0]).unwrap();
    let next1 = match processed1 {
        prism_sphinx::packet::ProcessedPacket::Forward { packet, .. } => packet,
        _ => unreachable!(),
    };
    let processed2 = process_sphinx_packet(&next1, &sks_3[1]).unwrap();
    let next2 = match processed2 {
        prism_sphinx::packet::ProcessedPacket::Forward { packet, .. } => packet,
        _ => unreachable!(),
    };
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = process_sphinx_packet(&next2, &sks_3[2]).unwrap();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute(
        "Sphinx Packet Relay Process (Hop 3/Destination)",
        samples,
        Some(PACKET_SIZE),
    ));

    // 8. Packet Serialization & Deserialization
    let packet_bytes = test_packet.to_bytes();
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = test_packet.to_bytes();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Sphinx Packet Serialize (32KB)", samples, Some(PACKET_SIZE)));

    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = SphinxPacket::from_bytes(&packet_bytes).unwrap();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Sphinx Packet Deserialize (32KB)", samples, Some(PACKET_SIZE)));

    // 9. Replay Filter Operations
    let mut filter = ReplayFilter::new(1024 * 1024, 7);
    let secret = [0x99u8; 32];
    let tag = ReplayFilter::derive_tag(&secret);

    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = ReplayFilter::derive_tag(&secret);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Replay Tag Derivation", samples, None));

    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = filter.might_contain(&tag);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Replay Bloom might_contain Lookup", samples, None));

    let mut samples = Vec::with_capacity(iters);
    for i in 0..iters {
        let mut s = [0u8; 32];
        s[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        let t = ReplayFilter::derive_tag(&s);
        let start = Instant::now();
        let _ = filter.insert(&t);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Replay Bloom Insert (Unique Tag)", samples, None));

    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = filter.insert(&tag);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Replay Bloom Insert (Duplicate/Replay)", samples, None));

    results
}
