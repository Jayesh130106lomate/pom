//! Post-Quantum Hybrid Sphinx packet implementation.
//!
//! Combines classical X25519 Diffie-Hellman with ML-KEM-768 (Kyber768) lattice-based
//! key encapsulation. This construction eliminates the Harvest-Now-Decrypt-Later
//! quantum vulnerability while preserving forward secrecy and mixnet layer unlinkability.

use hmac::Hmac;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher};

use prism_crypto::hybrid_kem::{
    encapsulate, decapsulate, HybridPublicKey, HybridSecretKey, HybridCiphertext,
};
use crate::constants::*;
use crate::errors::SphinxError;
use crate::header::{compute_header_mac, derive_hop_keys};
use crate::payload::{
    decrypt_inner_payload, decrypt_payload_layer, derive_inner_aead_key_and_nonce,
    encrypt_inner_payload, encrypt_payload_layer, pad_payload, unpad_payload,
};
use crate::routing::{PacketFlag, RoutingInfo};

type HmacSha256 = Hmac<Sha256>;

/// A route hop configured with a Post-Quantum Hybrid public key (X25519 + ML-KEM-768).
#[derive(Clone)]
pub struct PqRouteHop {
    pub routing: RoutingInfo,
    pub hybrid_public_key: HybridPublicKey,
}

/// A Post-Quantum Sphinx header containing layered hybrid KEM ciphertexts.
#[derive(Clone)]
pub struct PqSphinxHeader {
    pub version: u8,
    pub epoch_id: u32,
    /// Layered Hybrid KEM ciphertexts (one for each hop).
    pub ciphertexts: Vec<HybridCiphertext>,
    /// Encrypted routing information for intermediate hops.
    pub routing_info: Vec<u8>,
    /// HMAC-SHA-256 integrity tag for the current hop.
    pub mac: [u8; 32],
}

/// A complete Post-Quantum Sphinx packet.
#[derive(Clone)]
pub struct PqSphinxPacket {
    pub header: PqSphinxHeader,
    pub payload: Vec<u8>,
}

/// Processing result at a relay for a Post-Quantum Sphinx packet.
pub enum PqProcessedPacket {
    Forward {
        next_hop: std::net::SocketAddr,
        delay_seed: u32,
        packet: PqSphinxPacket,
        shared_secret: [u8; 32],
    },
    Destination {
        payload: Vec<u8>,
        shared_secret: [u8; 32],
    },
}

const ROUTING_STREAM_NONCE: [u8; 12] = *b"prism-pq-hdr";

fn generate_keystream(key: &[u8; 32], needed: usize) -> Vec<u8> {
    let mut keystream = vec![0u8; needed];
    let mut cipher = ChaCha20::new(key.into(), (&ROUTING_STREAM_NONCE).into());
    cipher.apply_keystream(&mut keystream);
    keystream
}

fn stream_cipher(key: &[u8; 32], data: &mut [u8]) {
    let mut cipher = ChaCha20::new(key.into(), (&ROUTING_STREAM_NONCE).into());
    cipher.apply_keystream(data);
}

fn shift_left(data: &[u8], blocks: usize) -> Vec<u8> {
    let shift = blocks * ROUTING_BLOCK_SIZE;
    let mut out = vec![0u8; data.len()];
    if shift < data.len() {
        out[..data.len() - shift].copy_from_slice(&data[shift..]);
    }
    out
}

/// Construct a Post-Quantum Sphinx packet.
pub fn create_pq_sphinx_packet(
    message: &[u8],
    route: &[PqRouteHop],
    epoch_id: u32,
) -> Result<PqSphinxPacket, SphinxError> {
    let num_hops = route.len();
    if num_hops == 0 {
        return Err(SphinxError::InvalidRoutingInfo("route cannot be empty".into()));
    }
    if num_hops > MAX_HOPS {
        return Err(SphinxError::TooManyHops { max: MAX_HOPS, requested: num_hops });
    }

    let available = PAYLOAD_PLAINTEXT_SIZE - 4;
    if message.len() > available {
        return Err(SphinxError::PayloadTooLarge { max: available, got: message.len() });
    }

    // Step 1: Encapsulate hybrid secrets for each hop (ML-KEM-768 + X25519)
    let mut shared_secrets = Vec::with_capacity(num_hops);
    let mut ciphertexts = Vec::with_capacity(num_hops);

    for hop in route {
        let (ct, ss) = encapsulate(&hop.hybrid_public_key);
        ciphertexts.push(ct);
        shared_secrets.push(ss.0);
    }

    // Step 2: Build routing info (beta_0) using closed-form linear Sphinx algorithm
    let mut ks = Vec::with_capacity(num_hops);
    for i in 0..num_hops {
        let hop_keys = derive_hop_keys(&shared_secrets[i]);
        ks.push(generate_keystream(&hop_keys.encryption_key, ROUTING_INFO_SIZE));
    }

    let mut phi: Vec<Vec<u8>> = Vec::with_capacity(num_hops);
    for i in 0..num_hops {
        let mut phi_i = vec![0u8; ROUTING_INFO_SIZE];
        for j in 0..i {
            let shifted_ks = shift_left(&ks[j], i - j);
            for (p, s) in phi_i.iter_mut().zip(shifted_ks.iter()) {
                *p ^= *s;
            }
        }
        phi.push(phi_i);
    }

    let mut beta_0 = vec![0u8; ROUTING_INFO_SIZE];

    for i in (0..num_hops).rev() {
        let gamma_next = if i == num_hops - 1 {
            [0u8; MAC_SIZE]
        } else {
            let mut beta_next = shift_left(&beta_0, i + 1);
            for (b, p) in beta_next.iter_mut().zip(phi[i + 1].iter()) {
                *b ^= *p;
            }
            let hop_next_keys = derive_hop_keys(&shared_secrets[i + 1]);
            let next_eph = ciphertexts[i + 1].x25519_ephemeral_pk.0.as_bytes();
            compute_header_mac(
                &hop_next_keys.mac_key,
                PROTOCOL_VERSION,
                epoch_id,
                next_eph,
                &beta_next,
            )
        };

        let routing_bytes = route[i].routing.to_bytes();
        let mut b_i = [0u8; ROUTING_BLOCK_SIZE];
        b_i[0..24].copy_from_slice(&routing_bytes);
        b_i[24..ROUTING_BLOCK_SIZE].copy_from_slice(&gamma_next);

        let offset = i * ROUTING_BLOCK_SIZE;
        for k in 0..ROUTING_BLOCK_SIZE {
            beta_0[offset + k] = b_i[k] ^ phi[i][k] ^ ks[i][k];
        }
    }

    let first_hop_keys = derive_hop_keys(&shared_secrets[0]);
    let first_eph = ciphertexts[0].x25519_ephemeral_pk.0.as_bytes();
    let header_mac = compute_header_mac(
        &first_hop_keys.mac_key,
        PROTOCOL_VERSION,
        epoch_id,
        first_eph,
        &beta_0,
    );

    let header = PqSphinxHeader {
        version: PROTOCOL_VERSION,
        epoch_id,
        ciphertexts,
        routing_info: beta_0,
        mac: header_mac,
    };

    // Step 3: Layered payload encryption
    let padded = pad_payload(message, PAYLOAD_PLAINTEXT_SIZE)?;
    let dest_secret = &shared_secrets[num_hops - 1];
    let (inner_key, inner_nonce) = derive_inner_aead_key_and_nonce(dest_secret);
    let inner_ciphertext = encrypt_inner_payload(&padded, &inner_key, &inner_nonce)?;
    let mut payload = inner_ciphertext.to_vec();

    if num_hops > 1 {
        for secret in shared_secrets[..num_hops - 1].iter().rev() {
            encrypt_payload_layer(secret, &mut payload);
        }
    }

    Ok(PqSphinxPacket { header, payload })
}

/// Process a Post-Quantum Sphinx packet at a relay.
pub fn process_pq_sphinx_packet(
    mut packet: PqSphinxPacket,
    relay_sk: &HybridSecretKey,
) -> Result<PqProcessedPacket, SphinxError> {
    if packet.header.ciphertexts.is_empty() {
        return Err(SphinxError::InvalidHeader("missing hybrid ciphertext".into()));
    }

    // Step 1: Pop the hybrid ciphertext for this hop and decapsulate shared secret
    let hop_ct = packet.header.ciphertexts.remove(0);
    let ss = decapsulate(relay_sk, &hop_ct);
    let shared_secret = ss.0;

    // Step 2: Derive hop keys
    let hop_keys = derive_hop_keys(&shared_secret);

    // Step 3: Verify MAC (constant-time)
    let eph_bytes = hop_ct.x25519_ephemeral_pk.0.as_bytes();
    let computed_mac = compute_header_mac(
        &hop_keys.mac_key,
        packet.header.version,
        packet.header.epoch_id,
        eph_bytes,
        &packet.header.routing_info,
    );

    if computed_mac.ct_eq(&packet.header.mac).unwrap_u8() == 0 {
        return Err(SphinxError::MacVerificationFailed { hop: 0 });
    }

    // Step 4: Decrypt routing info
    let mut decrypted_ri = packet.header.routing_info.clone();
    stream_cipher(&hop_keys.encryption_key, &mut decrypted_ri);

    let routing_data: [u8; 24] = decrypted_ri[0..24]
        .try_into()
        .map_err(|_| SphinxError::InvalidRoutingInfo("failed to extract routing block".into()))?;

    let routing = RoutingInfo::from_bytes(&routing_data)
        .ok_or_else(|| SphinxError::InvalidRoutingInfo("deserialization failed".into()))?;

    match routing.flag {
        PacketFlag::Forward | PacketFlag::SurbReply => {
            decrypt_payload_layer(&shared_secret, &mut packet.payload);

            let mut next_ri = vec![0u8; ROUTING_INFO_SIZE];
            let remaining = &decrypted_ri[ROUTING_BLOCK_SIZE..];
            next_ri[..remaining.len()].copy_from_slice(remaining);

            let mut next_mac = [0u8; 32];
            next_mac.copy_from_slice(&decrypted_ri[24..ROUTING_BLOCK_SIZE]);

            packet.header.routing_info = next_ri;
            packet.header.mac = next_mac;

            Ok(PqProcessedPacket::Forward {
                next_hop: routing.next_hop,
                delay_seed: routing.delay_seed,
                packet,
                shared_secret,
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
            let (key, nonce) = derive_inner_aead_key_and_nonce(&shared_secret);
            let padded_plaintext = decrypt_inner_payload(payload_array, &key, &nonce)?;
            let message = unpad_payload(&padded_plaintext)?;
            Ok(PqProcessedPacket::Destination {
                payload: message,
                shared_secret,
            })
        }
        _ => Err(SphinxError::InvalidRoutingInfo("unsupported packet flag for PQ Sphinx".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_crypto::hybrid_kem::generate_keypair;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn make_pq_route(num_hops: usize) -> (Vec<PqRouteHop>, Vec<HybridSecretKey>) {
        let mut hops = Vec::new();
        let mut secret_keys = Vec::new();

        for i in 0..num_hops {
            let (sk, pk) = generate_keypair();

            let flag = if i == num_hops - 1 {
                PacketFlag::FinalHop
            } else {
                PacketFlag::Forward
            };

            hops.push(PqRouteHop {
                routing: RoutingInfo {
                    next_hop: SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(10, 0, 0, (i + 1) as u8),
                        9000 + i as u16,
                    )),
                    delay_seed: (i * 100) as u32,
                    flag,
                    reserved: 0,
                },
                hybrid_public_key: pk,
            });

            secret_keys.push(sk);
        }

        (hops, secret_keys)
    }

    #[test]
    fn test_pq_sphinx_three_hop_end_to_end() {
        let (route, sks) = make_pq_route(3);
        let message = b"Post-Quantum Sphinx confidential message (ML-KEM-768 + X25519)";

        let packet = create_pq_sphinx_packet(message, &route, 1).unwrap();

        // Hop 0
        let res0 = process_pq_sphinx_packet(packet, &sks[0]).unwrap();
        let packet1 = match res0 {
            PqProcessedPacket::Forward { next_hop, packet, .. } => {
                assert_eq!(next_hop, route[0].routing.next_hop);
                packet
            }
            _ => panic!("hop 0 must forward"),
        };

        // Hop 1
        let res1 = process_pq_sphinx_packet(packet1, &sks[1]).unwrap();
        let packet2 = match res1 {
            PqProcessedPacket::Forward { next_hop, packet, .. } => {
                assert_eq!(next_hop, route[1].routing.next_hop);
                packet
            }
            _ => panic!("hop 1 must forward"),
        };

        // Hop 2 (Destination)
        let res2 = process_pq_sphinx_packet(packet2, &sks[2]).unwrap();
        match res2 {
            PqProcessedPacket::Destination { payload, .. } => {
                assert_eq!(payload, message.to_vec());
            }
            _ => panic!("hop 2 must reach destination"),
        }
    }
}
