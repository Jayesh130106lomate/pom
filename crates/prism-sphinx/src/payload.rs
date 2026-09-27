//! Sphinx payload encryption and decryption.
//!
//! The payload uses a SIZE-PRESERVING stream cipher (not AEAD) at each hop.
//! This is critical: AEAD adds a 16-byte auth tag per layer, which would
//! cause the payload to shrink at each hop, revealing position information.
//!
//! Integrity is ensured by the header MAC — if the header MAC verifies,
//! the shared secret (and thus the payload decryption) is correct.
//! The final recipient checks the message structure (padding format) for
//! end-to-end integrity.
//!
//! We derive a per-hop keystream via HKDF and XOR it with the payload.

use chacha20::ChaCha20;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use cipher::{KeyIvInit, StreamCipher};
use prism_crypto::kdf::hkdf_sha256;

use crate::constants::{PAYLOAD_PLAINTEXT_SIZE, PAYLOAD_SIZE};
use crate::errors::SphinxError;

const PAYLOAD_STREAM_NONCE: [u8; 12] = *b"prism-payld\0";

const INNER_AEAD_SALT: &[u8] = b"prism-inner-aead";
const INNER_AEAD_INFO: &[u8] = b"chacha20-poly1305";

/// Derive inner ChaCha20-Poly1305 AEAD key (32 bytes) and nonce (12 bytes)
/// from destination shared secret using HKDF-SHA-256.
pub fn derive_inner_aead_key_and_nonce(dest_shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let derived = hkdf_sha256(dest_shared_secret, INNER_AEAD_SALT, INNER_AEAD_INFO, 44);
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&derived[0..32]);
    nonce.copy_from_slice(&derived[32..44]);
    (key, nonce)
}

/// Encrypt and authenticate padded plaintext using ChaCha20-Poly1305 AEAD.
/// Plaintext must be exactly PAYLOAD_PLAINTEXT_SIZE (31,728 bytes).
/// Output is exactly PAYLOAD_SIZE (31,744 bytes), containing ciphertext (31,728 bytes) + tag (16 bytes).
pub fn encrypt_inner_payload(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<[u8; PAYLOAD_SIZE], SphinxError> {
    if plaintext.len() != PAYLOAD_PLAINTEXT_SIZE {
        return Err(SphinxError::CryptoError(format!(
            "invalid inner plaintext size: expected {}, got {}",
            PAYLOAD_PLAINTEXT_SIZE,
            plaintext.len()
        )));
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad: b"",
    };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| SphinxError::CryptoError("inner AEAD encryption failed".into()))?;

    if ciphertext.len() != PAYLOAD_SIZE {
        return Err(SphinxError::CryptoError(format!(
            "unexpected inner AEAD ciphertext length: expected {}, got {}",
            PAYLOAD_SIZE,
            ciphertext.len()
        )));
    }

    let mut out = [0u8; PAYLOAD_SIZE];
    out.copy_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt and authenticate payload using ChaCha20-Poly1305 AEAD.
/// Returns SphinxError::PayloadAuthenticationFailed if Poly1305 tag verification fails.
pub fn decrypt_inner_payload(
    payload: &[u8; PAYLOAD_SIZE],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, SphinxError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    let aead_payload = Payload {
        msg: payload.as_slice(),
        aad: b"",
    };
    cipher
        .decrypt(nonce, aead_payload)
        .map_err(|_| SphinxError::PayloadAuthenticationFailed)
}

/// Derive a keystream for payload encryption at a given hop using ChaCha20.
fn payload_stream_cipher(shared_secret: &[u8; 32], data: &mut [u8]) {
    // Derive a payload-specific key from the shared secret
    let payload_key_bytes = hkdf_sha256(shared_secret, b"prism-payload-key", b"payload", 32);
    let mut payload_key = [0u8; 32];
    payload_key.copy_from_slice(&payload_key_bytes);

    let mut cipher = ChaCha20::new((&payload_key).into(), (&PAYLOAD_STREAM_NONCE).into());
    cipher.apply_keystream(data);
}

/// Encrypt/decrypt one layer of payload at a relay.
/// This is the SAME operation for encryption and decryption (XOR is symmetric).
/// Size is perfectly preserved — no auth tag overhead.
pub fn encrypt_payload_layer(shared_secret: &[u8; 32], data: &mut [u8]) {
    payload_stream_cipher(shared_secret, data);
}

/// Decrypt one layer of payload at a relay (identical to encrypt — XOR).
pub fn decrypt_payload_layer(shared_secret: &[u8; 32], data: &mut [u8]) {
    payload_stream_cipher(shared_secret, data);
}

/// Apply all layers of encryption to a payload (client-side).
///
/// Encrypts from the innermost layer (destination) to the outermost (first hop).
/// Each layer is a size-preserving XOR stream cipher, so the payload size
/// is IDENTICAL at every hop.
pub fn encrypt_payload_all_layers(shared_secrets: &[[u8; 32]], payload: &mut [u8]) {
    // Encrypt in reverse order: last hop first (innermost), first hop last (outermost)
    for secret in shared_secrets.iter().rev() {
        encrypt_payload_layer(secret, payload);
    }
}

/// Pad plaintext to a fixed size before encryption.
///
/// Format: [data] [0x00 ... 0x00] [4-byte big-endian length of original data]
pub fn pad_payload(data: &[u8], target_size: usize) -> Result<Vec<u8>, SphinxError> {
    if data.len() + 4 > target_size {
        return Err(SphinxError::PayloadTooLarge {
            max: target_size - 4,
            got: data.len(),
        });
    }

    let mut padded = vec![0u8; target_size];
    padded[0..data.len()].copy_from_slice(data);
    let len_bytes = (data.len() as u32).to_be_bytes();
    padded[target_size - 4..].copy_from_slice(&len_bytes);

    Ok(padded)
}

/// Remove padding from decrypted payload.
pub fn unpad_payload(padded: &[u8]) -> Result<Vec<u8>, SphinxError> {
    if padded.len() < 4 {
        return Err(SphinxError::CryptoError("payload too short to unpad".into()));
    }

    let len_bytes: [u8; 4] = padded[padded.len() - 4..]
        .try_into()
        .map_err(|_| SphinxError::CryptoError("failed to read length".into()))?;
    let original_len = u32::from_be_bytes(len_bytes) as usize;

    if original_len > padded.len() - 4 {
        return Err(SphinxError::CryptoError(format!(
            "invalid padding length: {} > {}",
            original_len,
            padded.len() - 4
        )));
    }

    Ok(padded[0..original_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::PAYLOAD_SIZE;

    #[test]
    fn payload_single_layer_roundtrip() {
        let secret = [42u8; 32];
        let original = b"hello world, this is a test message for the Sphinx payload";
        let mut data = original.to_vec();

        encrypt_payload_layer(&secret, &mut data);
        assert_ne!(&data[..], &original[..]);

        decrypt_payload_layer(&secret, &mut data);
        assert_eq!(&data[..], &original[..]);
    }

    #[test]
    fn payload_size_preserved() {
        let secret = [99u8; 32];
        let original_len = 1000;
        let mut data = vec![0xAB; original_len];

        encrypt_payload_layer(&secret, &mut data);
        assert_eq!(data.len(), original_len, "size must not change after encryption");

        decrypt_payload_layer(&secret, &mut data);
        assert_eq!(data.len(), original_len, "size must not change after decryption");
    }

    #[test]
    fn payload_multi_layer_roundtrip() {
        let secrets = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let original = b"secret message through 3 hops";
        let mut data = original.to_vec();

        // Encrypt all layers (innermost first, outermost last)
        encrypt_payload_all_layers(&secrets, &mut data);
        assert_ne!(&data[..], &original[..]);

        // Decrypt layer by layer (first hop = outermost, strips first)
        decrypt_payload_layer(&secrets[0], &mut data);
        decrypt_payload_layer(&secrets[1], &mut data);
        decrypt_payload_layer(&secrets[2], &mut data);

        assert_eq!(&data[..], &original[..]);
    }

    #[test]
    fn payload_size_constant_across_layers() {
        let secrets = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let mut data = vec![0xFF; PAYLOAD_SIZE];
        let original_size = data.len();

        encrypt_payload_all_layers(&secrets, &mut data);
        assert_eq!(data.len(), original_size, "size must be constant after all layers");

        decrypt_payload_layer(&secrets[0], &mut data);
        assert_eq!(data.len(), original_size, "size must be constant after hop 0");

        decrypt_payload_layer(&secrets[1], &mut data);
        assert_eq!(data.len(), original_size, "size must be constant after hop 1");

        decrypt_payload_layer(&secrets[2], &mut data);
        assert_eq!(data.len(), original_size, "size must be constant after hop 2");
    }

    #[test]
    fn padding_roundtrip() {
        let data = b"short message";
        let padded = pad_payload(data, 1024).unwrap();
        assert_eq!(padded.len(), 1024);

        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(&unpadded[..], &data[..]);
    }

    #[test]
    fn padding_max_size() {
        let data = vec![0xAB; 1020];
        let padded = pad_payload(&data, 1024).unwrap();
        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn padding_too_large() {
        let data = vec![0xFF; 1021];
        assert!(pad_payload(&data, 1024).is_err());
    }

    #[test]
    fn test_inner_aead_roundtrip() {
        let secret = [0x5Au8; 32];
        let (key, nonce) = derive_inner_aead_key_and_nonce(&secret);

        let original_msg = b"Confidential mixnet payload test message";
        let padded = pad_payload(original_msg, PAYLOAD_PLAINTEXT_SIZE).unwrap();
        assert_eq!(padded.len(), PAYLOAD_PLAINTEXT_SIZE);

        let ciphertext = encrypt_inner_payload(&padded, &key, &nonce).unwrap();
        assert_eq!(ciphertext.len(), PAYLOAD_SIZE);

        let decrypted = decrypt_inner_payload(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(decrypted.len(), PAYLOAD_PLAINTEXT_SIZE);

        let unpadded = unpad_payload(&decrypted).unwrap();
        assert_eq!(unpadded.as_slice(), original_msg);
    }

    #[test]
    fn test_inner_aead_ciphertext_tamper_fails() {
        let secret = [0x77u8; 32];
        let (key, nonce) = derive_inner_aead_key_and_nonce(&secret);

        let original_msg = b"Transaction payload $1,000,000";
        let padded = pad_payload(original_msg, PAYLOAD_PLAINTEXT_SIZE).unwrap();

        let mut ciphertext = encrypt_inner_payload(&padded, &key, &nonce).unwrap();

        // Flip a single bit in the ciphertext region
        ciphertext[100] ^= 0x01;

        let result = decrypt_inner_payload(&ciphertext, &key, &nonce);
        assert!(
            matches!(result, Err(SphinxError::PayloadAuthenticationFailed)),
            "tampered ciphertext must fail Poly1305 tag verification"
        );
    }

    #[test]
    fn test_inner_aead_tag_tamper_fails() {
        let secret = [0x88u8; 32];
        let (key, nonce) = derive_inner_aead_key_and_nonce(&secret);

        let original_msg = b"Tag tampering detection test";
        let padded = pad_payload(original_msg, PAYLOAD_PLAINTEXT_SIZE).unwrap();

        let mut ciphertext = encrypt_inner_payload(&padded, &key, &nonce).unwrap();

        // Flip a bit in the Poly1305 tag (last 16 bytes)
        let last_idx = PAYLOAD_SIZE - 1;
        ciphertext[last_idx] ^= 0x80;

        let result = decrypt_inner_payload(&ciphertext, &key, &nonce);
        assert!(
            matches!(result, Err(SphinxError::PayloadAuthenticationFailed)),
            "tampered Poly1305 tag must fail authentication"
        );
    }

    #[test]
    fn test_inner_aead_wrong_key_fails() {
        let secret = [0x11u8; 32];
        let (key, nonce) = derive_inner_aead_key_and_nonce(&secret);

        let padded = pad_payload(b"hello", PAYLOAD_PLAINTEXT_SIZE).unwrap();
        let ciphertext = encrypt_inner_payload(&padded, &key, &nonce).unwrap();

        let wrong_key = [0x22u8; 32];
        let result = decrypt_inner_payload(&ciphertext, &wrong_key, &nonce);
        assert!(matches!(result, Err(SphinxError::PayloadAuthenticationFailed)));
    }

    #[test]
    fn test_inner_aead_wrong_nonce_fails() {
        let secret = [0x33u8; 32];
        let (key, nonce) = derive_inner_aead_key_and_nonce(&secret);

        let padded = pad_payload(b"hello", PAYLOAD_PLAINTEXT_SIZE).unwrap();
        let ciphertext = encrypt_inner_payload(&padded, &key, &nonce).unwrap();

        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 0x01;
        let result = decrypt_inner_payload(&ciphertext, &key, &wrong_nonce);
        assert!(matches!(result, Err(SphinxError::PayloadAuthenticationFailed)));
    }

    #[test]
    fn test_inner_aead_invalid_plaintext_size() {
        let secret = [0x44u8; 32];
        let (key, nonce) = derive_inner_aead_key_and_nonce(&secret);

        let bad_plaintext = vec![0u8; 100];
        let result = encrypt_inner_payload(&bad_plaintext, &key, &nonce);
        assert!(result.is_err());
    }
}
