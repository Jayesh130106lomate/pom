use std::time::Instant;
use crate::stats::BenchStats;
use prism_crypto::{
    aead::{aes256gcm_decrypt, aes256gcm_encrypt, xchacha20_decrypt, xchacha20_encrypt},
    hybrid_kem::{decapsulate as hybrid_decap, encapsulate as hybrid_encap, generate_keypair as hybrid_gen},
    kdf::hkdf_sha256,
    mac::{compute_mac, verify_mac},
    ml_kem::{decapsulate as ml_decap, encapsulate as ml_encap, generate_keypair as ml_gen},
    signature::{generate_signing_keypair, sign, verify},
    x25519::{diffie_hellman, generate_keypair as x25519_gen},
};

pub fn run_crypto_benchmarks(iters: usize) -> Vec<BenchStats> {
    let mut results = Vec::new();

    // 1. X25519 KeyGen
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = x25519_gen();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("X25519 Keypair Gen", samples, None));

    // 2. X25519 DH
    let (sec, _) = x25519_gen();
    let (_, pubk) = x25519_gen();
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = diffie_hellman(&sec, &pubk);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("X25519 Diffie-Hellman", samples, None));

    // 3. HKDF-SHA256 (32 bytes)
    let ikm = [0x42u8; 32];
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = hkdf_sha256(&ikm, b"salt", b"info", 32);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("HKDF-SHA256 (32B out)", samples, Some(32)));

    // 4. HKDF-SHA256 (96 bytes - Sphinx hop keys)
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = hkdf_sha256(&ikm, b"prism-sphinx", b"hop-keys", 96);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("HKDF-SHA256 (96B hop-keys)", samples, Some(96)));

    // 5. HMAC-SHA256 compute (280 bytes routing info)
    let mac_key = [0x11u8; 32];
    let routing_data = vec![0x33u8; 280];
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = compute_mac(&mac_key, &routing_data);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("HMAC-SHA256 Compute (280B)", samples, Some(280)));

    // 6. HMAC-SHA256 verify (constant-time)
    let expected_mac = compute_mac(&mac_key, &routing_data);
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = verify_mac(&mac_key, &routing_data, &expected_mac);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("HMAC-SHA256 Verify (280B)", samples, Some(280)));

    // 7. ML-KEM-768 KeyGen
    let pq_iters = (iters / 2).max(50);
    let mut samples = Vec::with_capacity(pq_iters);
    for _ in 0..pq_iters {
        let start = Instant::now();
        let _ = ml_gen();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("ML-KEM-768 Keypair Gen", samples, None));

    // 8. ML-KEM-768 Encap
    let (ml_sk, ml_pk) = ml_gen();
    let mut samples = Vec::with_capacity(pq_iters);
    for _ in 0..pq_iters {
        let start = Instant::now();
        let _ = ml_encap(&ml_pk);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("ML-KEM-768 Encapsulation", samples, None));

    // 9. ML-KEM-768 Decap
    let (ml_ct, _) = ml_encap(&ml_pk);
    let mut samples = Vec::with_capacity(pq_iters);
    for _ in 0..pq_iters {
        let start = Instant::now();
        let _ = ml_decap(&ml_sk, &ml_ct);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("ML-KEM-768 Decapsulation", samples, None));

    // 10. Hybrid KEM KeyGen
    let mut samples = Vec::with_capacity(pq_iters);
    for _ in 0..pq_iters {
        let start = Instant::now();
        let _ = hybrid_gen();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Hybrid KEM Keypair Gen", samples, None));

    // 11. Hybrid KEM Encap
    let (hyb_sk, hyb_pk) = hybrid_gen();
    let mut samples = Vec::with_capacity(pq_iters);
    for _ in 0..pq_iters {
        let start = Instant::now();
        let _ = hybrid_encap(&hyb_pk);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Hybrid KEM Encapsulation", samples, None));

    // 12. Hybrid KEM Decap
    let (hyb_ct, _) = hybrid_encap(&hyb_pk);
    let mut samples = Vec::with_capacity(pq_iters);
    for _ in 0..pq_iters {
        let start = Instant::now();
        let _ = hybrid_decap(&hyb_sk, &hyb_ct);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Hybrid KEM Decapsulation", samples, None));

    // 13. AEAD AES-256-GCM Encrypt (1KB)
    let aead_key = [0x55u8; 32];
    let gcm_nonce = [0x77u8; 12];
    let payload_1k = vec![0xAAu8; 1024];
    let aad = b"header-aad";
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = aes256gcm_encrypt(&aead_key, &gcm_nonce, &payload_1k, aad);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("AES-256-GCM Encrypt (1KB)", samples, Some(1024)));

    // 14. AEAD AES-256-GCM Decrypt (1KB)
    let gcm_ct = aes256gcm_encrypt(&aead_key, &gcm_nonce, &payload_1k, aad).unwrap();
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = aes256gcm_decrypt(&aead_key, &gcm_nonce, &gcm_ct, aad);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("AES-256-GCM Decrypt (1KB)", samples, Some(1024)));

    // 15. AEAD XChaCha20-Poly1305 Encrypt (1KB)
    let xchacha_nonce = [0x88u8; 24];
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = xchacha20_encrypt(&aead_key, &xchacha_nonce, &payload_1k, aad);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("XChaCha20-Poly1305 Encrypt (1KB)", samples, Some(1024)));

    // 16. AEAD XChaCha20-Poly1305 Decrypt (1KB)
    let xchacha_ct = xchacha20_encrypt(&aead_key, &xchacha_nonce, &payload_1k, aad).unwrap();
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = xchacha20_decrypt(&aead_key, &xchacha_nonce, &xchacha_ct, aad);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("XChaCha20-Poly1305 Decrypt (1KB)", samples, Some(1024)));

    // 17. Ed25519 Sign (64B)
    let (sign_sk, sign_vk) = generate_signing_keypair();
    let sig_msg = vec![0x99u8; 64];
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = sign(&sign_sk, &sig_msg);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Ed25519 Sign (64B)", samples, Some(64)));

    // 18. Ed25519 Verify (64B)
    let sig = sign(&sign_sk, &sig_msg);
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let _ = verify(&sign_vk, &sig_msg, &sig);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    results.push(BenchStats::compute("Ed25519 Verify (64B)", samples, Some(64)));

    results
}
