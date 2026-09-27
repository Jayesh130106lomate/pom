//! Sphinx header construction and processing.
//!
//! Implements the Sphinx mix format (Danezis & Goldberg, 2009) with correct
//! ephemeral key blinding using X25519 Diffie-Hellman.
//!
//! Key insight: At each hop, the ephemeral public key is "blinded" by multiplying
//! it with a blinding factor derived from the shared secret. The client can
//! pre-compute what each relay will see by chaining DH operations.
//!
//! The header contains:
//! 1. Protocol version (1 byte)
//! 2. Epoch ID (4 bytes)
//! 3. Ephemeral public key (32 bytes, re-blinded at each hop)
//! 4. Encrypted routing info (per-hop blocks, fixed size)
//! 5. Overall MAC (32 bytes)
//! 6. Padding to HEADER_SIZE

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use prism_crypto::kdf::hkdf_sha256;
use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher};

use crate::constants::*;
use crate::errors::SphinxError;
use crate::routing::{RouteHop, RoutingInfo};

type HmacSha256 = Hmac<Sha256>;

/// Derived keys for a single hop.
/// No hop_index: the shared secret is already unique per hop because each
/// relay has a different key and the ephemeral key is re-blinded.
#[derive(Debug)]
pub struct HopKeys {
    /// Key for encrypting/decrypting the routing info and payload.
    pub encryption_key: [u8; 32],
    /// Key for computing/verifying the MAC.
    pub mac_key: [u8; 32],
    /// Factor for re-blinding the ephemeral public key.
    pub blinding_factor: [u8; 32],
}

/// Derive per-hop keys from a shared secret.
///
/// The shared secret is already unique per hop (different relay key + blinded
/// ephemeral key), so no hop_index is needed in the derivation.
pub fn derive_hop_keys(shared_secret: &[u8; 32]) -> HopKeys {
    let derived = hkdf_sha256(shared_secret, b"prism-sphinx", b"hop-keys", 96);

    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    let mut blind = [0u8; 32];

    enc_key.copy_from_slice(&derived[0..32]);
    mac_key.copy_from_slice(&derived[32..64]);
    blind.copy_from_slice(&derived[64..96]);

    // Clamp blinding factor for X25519 scalar multiplication
    blind[0] &= 248;
    blind[31] &= 127;
    blind[31] |= 64;

    HopKeys {
        encryption_key: enc_key,
        mac_key,
        blinding_factor: blind,
    }
}

const ROUTING_STREAM_NONCE: [u8; 12] = *b"prism-header";

/// Generate a keystream via ChaCha20 stream cipher.
fn generate_keystream(key: &[u8; 32], needed: usize) -> Vec<u8> {
    let mut keystream = vec![0u8; needed];
    let mut cipher = ChaCha20::new(key.into(), (&ROUTING_STREAM_NONCE).into());
    cipher.apply_keystream(&mut keystream);
    keystream
}

/// XOR-based stream cipher for routing info encryption using ChaCha20.
fn stream_cipher(key: &[u8; 32], data: &mut [u8]) {
    let mut cipher = ChaCha20::new(key.into(), (&ROUTING_STREAM_NONCE).into());
    cipher.apply_keystream(data);
}

/// Shift data left by `blocks` routing blocks and zero-pad the tail.
fn shift_left(data: &[u8], blocks: usize) -> Vec<u8> {
    let shift = blocks * ROUTING_BLOCK_SIZE;
    let mut out = vec![0u8; data.len()];
    if shift < data.len() {
        out[..data.len() - shift].copy_from_slice(&data[shift..]);
    }
    out
}

/// Compute MAC over version, epoch_id, ephemeral_pk, and routing_info using HMAC-SHA-256.
pub fn compute_header_mac(
    mac_key: &[u8; 32],
    version: u8,
    epoch_id: u32,
    ephemeral_pk: &[u8; 32],
    routing_info: &[u8],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC key size is valid");
    mac.update(&[version]);
    mac.update(&epoch_id.to_be_bytes());
    mac.update(ephemeral_pk);
    mac.update(routing_info);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    output
}

/// Verify MAC using constant-time comparison (prevents timing side-channels).
pub fn verify_header_mac(
    mac_key: &[u8; 32],
    version: u8,
    epoch_id: u32,
    ephemeral_pk: &[u8; 32],
    routing_info: &[u8],
    expected_mac: &[u8; 32],
) -> Result<(), SphinxError> {
    let computed = compute_header_mac(mac_key, version, epoch_id, ephemeral_pk, routing_info);
    if computed.ct_eq(expected_mac).unwrap_u8() == 0 {
        return Err(SphinxError::MacVerificationFailed { hop: 0 });
    }
    Ok(())
}

/// A constructed Sphinx header ready for transmission.
#[derive(Debug, Clone)]
pub struct SphinxHeader {
    /// Protocol version.
    pub version: u8,
    /// Epoch identifier.
    pub epoch_id: u32,
    /// Ephemeral X25519 public key (re-blinded at each hop).
    pub ephemeral_pk: [u8; 32],
    /// Encrypted routing information (all hops, padded to fixed size).
    pub routing_info: Vec<u8>,
    /// MAC over the routing info for the current hop.
    pub mac: [u8; 32],
}

impl SphinxHeader {
    /// Serialize the header to exactly HEADER_SIZE bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE);
        buf.push(self.version);
        buf.extend_from_slice(&self.epoch_id.to_be_bytes());
        buf.extend_from_slice(&self.ephemeral_pk);
        buf.extend_from_slice(&self.routing_info);
        buf.extend_from_slice(&self.mac);
        buf.resize(HEADER_SIZE, 0);
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, SphinxError> {
        if data.len() < HEADER_SIZE {
            return Err(SphinxError::InvalidHeader(format!(
                "header too short: {} < {}",
                data.len(),
                HEADER_SIZE
            )));
        }

        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(SphinxError::UnsupportedVersion(version));
        }

        let epoch_id = u32::from_be_bytes(data[1..5].try_into().unwrap());
        let mut ephemeral_pk = [0u8; 32];
        ephemeral_pk.copy_from_slice(&data[5..37]);

        let ri_start = 37;
        let ri_end = ri_start + ROUTING_INFO_SIZE;
        let routing_info = data[ri_start..ri_end].to_vec();

        let mac_start = ri_end;
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[mac_start..mac_start + 32]);

        Ok(SphinxHeader {
            version,
            epoch_id,
            ephemeral_pk,
            routing_info,
            mac,
        })
    }
}

/// Build a Sphinx header for a given route.
///
/// Correct Sphinx blinding algorithm:
/// - Client generates ephemeral keypair (eph_secret, alpha_0)
/// - For hop i, the client computes the shared secret that relay i will compute
///   when it receives alpha_i (the i-times-blinded ephemeral public key).
/// - The shared secret is computed by chaining DH operations through all
///   prior blinding factors.
///
/// Returns the header and the shared secrets for each hop (for payload encryption).
pub fn build_header(
    route: &[RouteHop],
    epoch_id: u32,
) -> Result<(SphinxHeader, Vec<[u8; 32]>), SphinxError> {
    let num_hops = route.len();
    if num_hops > MAX_HOPS {
        return Err(SphinxError::TooManyHops {
            max: MAX_HOPS,
            requested: num_hops,
        });
    }
    if num_hops == 0 {
        return Err(SphinxError::InvalidRoutingInfo(
            "route must have at least one hop".into(),
        ));
    }

    // Generate ephemeral keypair
    let ephemeral_secret = X25519Secret::random_from_rng(rand::thread_rng());
    let ephemeral_public = X25519Public::from(&ephemeral_secret);

    // Phase 1: Compute shared secrets and blinding factors for all hops.
    //
    // For hop i, the relay will compute: s_i = DH(relay_sk_i, alpha_i)
    // where alpha_i = b_{i-1} * b_{i-2} * ... * b_0 * alpha_0
    //
    // The client computes the same value by chaining DH:
    //   temp = DH(eph_secret, relay_pk_i)
    //   for j in 0..i: temp = DH(b_j, temp_as_public_key)
    //   s_i = temp
    //
    // This works because X25519 DH is commutative over scalar multiplication.
    let mut shared_secrets = Vec::with_capacity(num_hops);
    let mut blinding_factors: Vec<[u8; 32]> = Vec::with_capacity(num_hops);
    let mut alphas = Vec::with_capacity(num_hops + 1);
    alphas.push(ephemeral_public);

    for (i, hop) in route.iter().enumerate() {
        let relay_pk = X25519Public::from(hop.public_key);

        // Compute shared secret for hop i
        // Start with DH(eph_secret, relay_pk_i)
        let base_dh = ephemeral_secret.diffie_hellman(&relay_pk);
        let mut shared_point = *base_dh.as_bytes();

        // Apply each prior blinding factor via DH
        for j in 0..i {
            let blind_sk = X25519Secret::from(blinding_factors[j]);
            let point_as_pk = X25519Public::from(shared_point);
            shared_point = *blind_sk.diffie_hellman(&point_as_pk).as_bytes();
        }

        shared_secrets.push(shared_point);

        // Derive hop keys (blinding factor included)
        let hop_keys = derive_hop_keys(&shared_point);
        blinding_factors.push(hop_keys.blinding_factor);

        // Compute alpha_{i+1} = DH(blinding_factor, alpha_i)
        let blind_sk = X25519Secret::from(hop_keys.blinding_factor);
        let next_alpha = X25519Public::from(*blind_sk.diffie_hellman(&alphas[i]).as_bytes());
        alphas.push(next_alpha);
    }

    // Phase 2: Build routing info (beta_0) using the Sphinx closed-form linear algorithm.
    // Each relay i decrypts: decrypted_i = beta_i XOR KS_i
    // strips its block: beta_{i+1} = shift_left(decrypted_i, 1) = shift_left(beta_i, 1) XOR shift_left(KS_i, 1).
    // In general: beta_i = shift_left(beta_0, i) XOR Phi_i,
    // where Phi_i = XOR_{j=0}^{i-1} shift_left(KS_j, i - j).
    let mut ks = Vec::with_capacity(num_hops);
    for i in 0..num_hops {
        let hop_keys = derive_hop_keys(&shared_secrets[i]);
        ks.push(generate_keystream(&hop_keys.encryption_key, ROUTING_INFO_SIZE));
    }

    // Precompute Phi_i for each hop i in 0..num_hops
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

    // Work backwards from i = num_hops - 1 down to 0
    let mut beta_0 = vec![0u8; ROUTING_INFO_SIZE];

    for i in (0..num_hops).rev() {
        let gamma_next = if i == num_hops - 1 {
            [0u8; MAC_SIZE]
        } else {
            // Compute beta_{i+1} = shift_left(beta_0, i + 1) XOR Phi_{i+1}
            let mut beta_next = shift_left(&beta_0, i + 1);
            for (b, p) in beta_next.iter_mut().zip(phi[i + 1].iter()) {
                *b ^= *p;
            }
            let hop_next_keys = derive_hop_keys(&shared_secrets[i + 1]);
            let next_ephemeral = alphas[i + 1].to_bytes();
            compute_header_mac(
                &hop_next_keys.mac_key,
                PROTOCOL_VERSION,
                epoch_id,
                &next_ephemeral,
                &beta_next,
            )
        };

        // B_i = routing_bytes (24) || gamma_next (32)
        let routing_bytes = route[i].routing.to_bytes();
        let mut b_i = [0u8; ROUTING_BLOCK_SIZE];
        b_i[0..24].copy_from_slice(&routing_bytes);
        b_i[24..ROUTING_BLOCK_SIZE].copy_from_slice(&gamma_next);

        // beta_0[i*s .. (i+1)*s] = B_i XOR Phi_i[0..s] XOR KS_i[0..s]
        let offset = i * ROUTING_BLOCK_SIZE;
        for k in 0..ROUTING_BLOCK_SIZE {
            beta_0[offset + k] = b_i[k] ^ phi[i][k] ^ ks[i][k];
        }
    }

    // Compute the outer MAC for the first hop
    let first_hop_keys = derive_hop_keys(&shared_secrets[0]);
    let header_mac = compute_header_mac(
        &first_hop_keys.mac_key,
        PROTOCOL_VERSION,
        epoch_id,
        &ephemeral_public.to_bytes(),
        &beta_0,
    );

    let header = SphinxHeader {
        version: PROTOCOL_VERSION,
        epoch_id,
        ephemeral_pk: ephemeral_public.to_bytes(),
        routing_info: beta_0,
        mac: header_mac,
    };

    Ok((header, shared_secrets))
}

/// Result of processing a Sphinx header at a relay.
pub struct ProcessedHeader {
    /// The routing info for this hop.
    pub routing: RoutingInfo,
    /// The header to forward to the next hop.
    pub next_header: SphinxHeader,
    /// The shared secret for this hop (for payload decryption and replay detection).
    pub shared_secret: [u8; 32],
}

/// Process a Sphinx header at a relay node.
///
/// The relay:
/// 1. Computes shared secret from its secret key and the ephemeral key
/// 2. Derives encryption/MAC/blinding keys
/// 3. Verifies the MAC (constant-time)
/// 4. Decrypts its routing block
/// 5. Extracts routing info
/// 6. Re-blinds the ephemeral key for the next hop
/// 7. Constructs the next header
pub fn process_header(
    header: &SphinxHeader,
    relay_secret_key: &[u8; 32],
) -> Result<ProcessedHeader, SphinxError> {
    // Step 1: Compute shared secret
    let relay_sk = X25519Secret::from(*relay_secret_key);
    let ephemeral_pk = X25519Public::from(header.ephemeral_pk);
    let shared = relay_sk.diffie_hellman(&ephemeral_pk);
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(shared.as_bytes());

    // Step 2: Derive keys
    let hop_keys = derive_hop_keys(&shared_secret);

    // Step 3: Verify MAC (constant-time comparison)
    let computed_mac = compute_header_mac(
        &hop_keys.mac_key,
        header.version,
        header.epoch_id,
        &header.ephemeral_pk,
        &header.routing_info,
    );
    if computed_mac.ct_eq(&header.mac).unwrap_u8() == 0 {
        return Err(SphinxError::MacVerificationFailed { hop: 0 });
    }

    // Step 4: Decrypt routing info
    let mut decrypted_ri = header.routing_info.clone();
    stream_cipher(&hop_keys.encryption_key, &mut decrypted_ri);

    // Step 5: Extract this hop's routing block
    let routing_data: [u8; 24] = decrypted_ri[0..24]
        .try_into()
        .map_err(|_| SphinxError::InvalidRoutingInfo("failed to extract routing block".into()))?;

    let routing = RoutingInfo::from_bytes(&routing_data).ok_or_else(|| {
        SphinxError::InvalidRoutingInfo("failed to deserialize routing info".into())
    })?;

    // Step 6: Shift routing info left, pad end with zeros
    let mut next_ri = vec![0u8; ROUTING_INFO_SIZE];
    let remaining = &decrypted_ri[ROUTING_BLOCK_SIZE..];
    next_ri[..remaining.len()].copy_from_slice(remaining);

    // Step 7: Re-blind ephemeral public key
    let blind = X25519Secret::from(hop_keys.blinding_factor);
    let new_ephemeral = X25519Public::from(*blind.diffie_hellman(&ephemeral_pk).as_bytes());

    // Compute MAC for the next hop using the next hop's keys.
    // The next hop will derive its own keys from DH(next_relay_sk, new_ephemeral),
    // but we don't know next_relay_sk. Instead, the MAC for the next hop was
    // already embedded INSIDE the encrypted routing info by build_header.
    // We extract it from the inner_mac that was placed at bytes [24..56] of
    // the decrypted routing info.
    let mut next_mac = [0u8; 32];
    next_mac.copy_from_slice(&decrypted_ri[24..ROUTING_BLOCK_SIZE]);

    let next_header = SphinxHeader {
        version: header.version,
        epoch_id: header.epoch_id,
        ephemeral_pk: new_ephemeral.to_bytes(),
        routing_info: next_ri,
        mac: next_mac,
    };

    Ok(ProcessedHeader {
        routing,
        next_header,
        shared_secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::PacketFlag;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn make_route(num_hops: usize) -> (Vec<RouteHop>, Vec<[u8; 32]>) {
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
    fn header_build_and_serialize() {
        let (route, _sks) = make_route(3);
        let (header, secrets) = build_header(&route, 1).unwrap();

        assert_eq!(secrets.len(), 3);
        assert_eq!(header.version, PROTOCOL_VERSION);
        assert_eq!(header.epoch_id, 1);

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);

        let recovered = SphinxHeader::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.version, PROTOCOL_VERSION);
        assert_eq!(recovered.epoch_id, 1);
        assert_eq!(recovered.ephemeral_pk, header.ephemeral_pk);
    }

    #[test]
    fn header_too_many_hops() {
        let (route, _) = make_route(MAX_HOPS + 1);
        let result = build_header(&route, 1);
        assert!(result.is_err());
    }

    #[test]
    fn stream_cipher_roundtrip() {
        let key = [42u8; 32];
        let original = b"hello world, this is a test of the stream cipher!";
        let mut data = original.to_vec();
        stream_cipher(&key, &mut data);
        assert_ne!(&data[..], &original[..]);
        stream_cipher(&key, &mut data);
        assert_eq!(&data[..], &original[..]);
    }

    #[test]
    fn mac_verification_constant_time() {
        let key = [7u8; 32];
        let version = PROTOCOL_VERSION;
        let epoch_id = 42u32;
        let ephemeral_pk = [9u8; 32];
        let routing_info = b"some routing information";

        let mac = compute_header_mac(&key, version, epoch_id, &ephemeral_pk, routing_info);
        assert!(verify_header_mac(&key, version, epoch_id, &ephemeral_pk, routing_info, &mac).is_ok());

        // 1. Tamper routing_info
        let mut tampered_ri = routing_info.to_vec();
        tampered_ri[0] ^= 1;
        assert!(verify_header_mac(&key, version, epoch_id, &ephemeral_pk, &tampered_ri, &mac).is_err());

        // 2. Tamper version
        assert!(verify_header_mac(&key, version ^ 1, epoch_id, &ephemeral_pk, routing_info, &mac).is_err());

        // 3. Tamper epoch_id
        assert!(verify_header_mac(&key, version, epoch_id ^ 1, &ephemeral_pk, routing_info, &mac).is_err());

        // 4. Tamper ephemeral_pk
        let mut tampered_pk = ephemeral_pk;
        tampered_pk[0] ^= 1;
        assert!(verify_header_mac(&key, version, epoch_id, &tampered_pk, routing_info, &mac).is_err());

        // 5. Wrong key
        let wrong_key = [8u8; 32];
        assert!(verify_header_mac(&wrong_key, version, epoch_id, &ephemeral_pk, routing_info, &mac).is_err());
    }

    // CRITICAL TEST: Verify multi-hop header processing works correctly.
    // This tests the fix for bugs C1 and C2.
    #[test]
    fn header_multihop_processing() {
        for num_hops in 1..=5 {
            let (route, sks) = make_route(num_hops);
            let (header, client_secrets) = build_header(&route, 1).unwrap();

            let mut current_header = header;

            for i in 0..num_hops {
                let result = process_header(&current_header, &sks[i]);
                assert!(
                    result.is_ok(),
                    "MAC verification failed at hop {} of {} (num_hops={})",
                    i,
                    num_hops,
                    num_hops
                );

                let processed = result.unwrap();

                // Verify shared secret matches what the client computed
                assert_eq!(
                    processed.shared_secret, client_secrets[i],
                    "Shared secret mismatch at hop {} of {}",
                    i, num_hops
                );

                // Verify routing info
                assert_eq!(
                    processed.routing.next_hop,
                    route[i].routing.next_hop,
                    "Routing mismatch at hop {} of {}",
                    i, num_hops
                );
                assert_eq!(processed.routing.flag, route[i].routing.flag);
                assert_eq!(processed.routing.delay_seed, route[i].routing.delay_seed);

                current_header = processed.next_header;
            }
        }
    }

    #[test]
    fn header_tamper_detection() {
        let (route, sks) = make_route(3);
        let (mut header, _) = build_header(&route, 1).unwrap();

        // Tamper with routing info — single bit flip
        header.routing_info[10] ^= 0x01;

        let result = process_header(&header, &sks[0]);
        assert!(result.is_err(), "Tampered header should fail MAC verification");
    }

    #[test]
    fn header_tamper_epoch_id_detection() {
        let (route, sks) = make_route(3);
        let (mut header, _) = build_header(&route, 100).unwrap();

        // Tamper with epoch_id on header
        header.epoch_id ^= 0x01;

        let result = process_header(&header, &sks[0]);
        assert!(
            matches!(result, Err(SphinxError::MacVerificationFailed { .. })),
            "Tampered epoch_id must cause MacVerificationFailed"
        );
    }

    #[test]
    fn header_tamper_version_detection() {
        let (route, sks) = make_route(3);
        let (mut header, _) = build_header(&route, 1).unwrap();

        // Tamper with version
        header.version ^= 0x01;

        let result = process_header(&header, &sks[0]);
        assert!(
            matches!(result, Err(SphinxError::MacVerificationFailed { .. })),
            "Tampered version must cause MacVerificationFailed"
        );
    }

    #[test]
    fn header_tamper_ephemeral_pk_detection() {
        let (route, sks) = make_route(3);
        let (mut header, _) = build_header(&route, 1).unwrap();

        // Tamper with ephemeral_pk
        header.ephemeral_pk[5] ^= 0x01;

        let result = process_header(&header, &sks[0]);
        assert!(
            matches!(result, Err(SphinxError::MacVerificationFailed { .. })),
            "Tampered ephemeral_pk must cause MacVerificationFailed"
        );
    }

    #[test]
    fn test_wire_tampering_epoch_id_fails_mac_at_hop1() {
        let (route, sks) = make_route(3);
        let (header, _) = build_header(&route, 100).unwrap();
        let mut bytes = header.to_bytes();

        // Tamper with epoch_id field on wire (bytes 1..5)
        bytes[1] ^= 0x01;

        let tampered_header = SphinxHeader::from_bytes(&bytes).unwrap();
        let result = process_header(&tampered_header, &sks[0]);
        assert!(
            matches!(result, Err(SphinxError::MacVerificationFailed { .. })),
            "Wire tampering with epoch_id must trigger MacVerificationFailed at hop 1"
        );
    }
}
