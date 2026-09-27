use crate::x25519::{self, X25519Secret, X25519Public};
use crate::ml_kem::{self, MlKemSecretKey, MlKemPublicKey, MlKemCiphertext};
use crate::kdf::hkdf_sha256;
use zeroize::Zeroize;
use pqcrypto_traits::kem::SharedSecret;

#[derive(Clone)]
pub struct HybridPublicKey {
    pub x25519: X25519Public,
    pub mlkem: MlKemPublicKey,
}

impl HybridPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + self.mlkem.as_bytes().len());
        buf.extend_from_slice(self.x25519.0.as_bytes());
        buf.extend_from_slice(self.mlkem.as_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::errors::CryptoError> {
        if bytes.len() < 32 {
            return Err(crate::errors::CryptoError::KdfError);
        }
        let mut x25519_bytes = [0u8; 32];
        x25519_bytes.copy_from_slice(&bytes[0..32]);
        let x25519 = X25519Public(x25519_dalek::PublicKey::from(x25519_bytes));
        let mlkem = MlKemPublicKey::from_bytes(&bytes[32..])?;
        Ok(HybridPublicKey { x25519, mlkem })
    }
}

pub struct HybridSecretKey {
    pub x25519: X25519Secret,
    pub mlkem: MlKemSecretKey,
}

impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for HybridSecretKey {
    fn zeroize(&mut self) {
        self.x25519.zeroize();
    }
}

#[derive(Clone)]
pub struct HybridCiphertext {
    pub x25519_ephemeral_pk: X25519Public,
    pub mlkem_ct: MlKemCiphertext,
}

impl HybridCiphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + self.mlkem_ct.as_bytes().len());
        buf.extend_from_slice(self.x25519_ephemeral_pk.0.as_bytes());
        buf.extend_from_slice(self.mlkem_ct.as_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::errors::CryptoError> {
        if bytes.len() < 32 {
            return Err(crate::errors::CryptoError::KdfError);
        }
        let mut x25519_bytes = [0u8; 32];
        x25519_bytes.copy_from_slice(&bytes[0..32]);
        let x25519_ephemeral_pk = X25519Public(x25519_dalek::PublicKey::from(x25519_bytes));
        let mlkem_ct = MlKemCiphertext::from_bytes(&bytes[32..])?;
        Ok(HybridCiphertext {
            x25519_ephemeral_pk,
            mlkem_ct,
        })
    }
}

pub struct HybridSharedSecret(pub [u8; 32]);

pub fn generate_keypair() -> (HybridSecretKey, HybridPublicKey) {
    let (x25519_sk, x25519_pk) = x25519::generate_keypair();
    let (mlkem_sk, mlkem_pk) = ml_kem::generate_keypair();
    
    (
        HybridSecretKey { x25519: x25519_sk, mlkem: mlkem_sk },
        HybridPublicKey { x25519: x25519_pk, mlkem: mlkem_pk }
    )
}

pub fn encapsulate(pk: &HybridPublicKey) -> (HybridCiphertext, HybridSharedSecret) {
    let (eph_sk, eph_pk) = x25519::generate_keypair();
    let x25519_shared = x25519::diffie_hellman(&eph_sk, &pk.x25519);
    
    let (mlkem_ct, mlkem_shared) = ml_kem::encapsulate(&pk.mlkem);
    
    let mut combined = Vec::new();
    combined.extend_from_slice(x25519_shared.as_bytes());
    combined.extend_from_slice(mlkem_shared.0.as_bytes());
    
    const HYBRID_KEM_SALT: &[u8] = b"prism-hybrid-kem-v1-salt";
    let derived = hkdf_sha256(&combined, HYBRID_KEM_SALT, b"prism-hybrid-kem", 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&derived);
    
    (
        HybridCiphertext { x25519_ephemeral_pk: eph_pk, mlkem_ct },
        HybridSharedSecret(out)
    )
}

pub fn decapsulate(sk: &HybridSecretKey, ct: &HybridCiphertext) -> HybridSharedSecret {
    let x25519_shared = x25519::diffie_hellman(&sk.x25519, &ct.x25519_ephemeral_pk);
    let mlkem_shared = ml_kem::decapsulate(&sk.mlkem, &ct.mlkem_ct);
    
    let mut combined = Vec::new();
    combined.extend_from_slice(x25519_shared.as_bytes());
    combined.extend_from_slice(mlkem_shared.0.as_bytes());
    
    const HYBRID_KEM_SALT: &[u8] = b"prism-hybrid-kem-v1-salt";
    let derived = hkdf_sha256(&combined, HYBRID_KEM_SALT, b"prism-hybrid-kem", 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&derived);
    
    HybridSharedSecret(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem() {
        let (sk, pk) = generate_keypair();
        let (ct, ss_enc) = encapsulate(&pk);
        let ss_dec = decapsulate(&sk, &ct);
        
        assert_eq!(ss_enc.0, ss_dec.0);
    }

    #[test]
    fn test_hybrid_serialization_roundtrip() {
        let (sk, pk) = generate_keypair();
        let pk_bytes = pk.to_bytes();
        let pk_recovered = HybridPublicKey::from_bytes(&pk_bytes).unwrap();

        let (ct, ss_enc) = encapsulate(&pk_recovered);
        let ct_bytes = ct.to_bytes();
        let ct_recovered = HybridCiphertext::from_bytes(&ct_bytes).unwrap();

        let ss_dec = decapsulate(&sk, &ct_recovered);
        assert_eq!(ss_enc.0, ss_dec.0);
    }
}
