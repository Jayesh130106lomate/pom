use pqcrypto_kyber::kyber768::*;
use pqcrypto_traits::kem::{PublicKey as PkTrait, SecretKey as SkTrait, Ciphertext as CtTrait};
use crate::errors::CryptoError;

pub struct MlKemSecretKey(pub SecretKey);
#[derive(Clone)]
pub struct MlKemPublicKey(pub PublicKey);
#[derive(Clone)]
pub struct MlKemCiphertext(pub Ciphertext);
pub struct SharedSecret(pub pqcrypto_kyber::kyber768::SharedSecret);

impl MlKemPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        PublicKey::from_bytes(bytes).map(MlKemPublicKey).map_err(|_| CryptoError::KdfError)
    }
}

impl MlKemSecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        SecretKey::from_bytes(bytes).map(MlKemSecretKey).map_err(|_| CryptoError::KdfError)
    }
}

impl MlKemCiphertext {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ciphertext::from_bytes(bytes).map(MlKemCiphertext).map_err(|_| CryptoError::KdfError)
    }
}

pub fn generate_keypair() -> (MlKemSecretKey, MlKemPublicKey) {
    let (pk, sk) = keypair();
    (MlKemSecretKey(sk), MlKemPublicKey(pk))
}

pub fn encapsulate(pk: &MlKemPublicKey) -> (MlKemCiphertext, SharedSecret) {
    let (ss, ct) = pqcrypto_kyber::kyber768::encapsulate(&pk.0);
    (MlKemCiphertext(ct), SharedSecret(ss))
}

pub fn decapsulate(sk: &MlKemSecretKey, ct: &MlKemCiphertext) -> SharedSecret {
    let ss = pqcrypto_kyber::kyber768::decapsulate(&ct.0, &sk.0);
    SharedSecret(ss)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::kem::SharedSecret;

    #[test]
    fn test_mlkem() {
        let (sk, pk) = generate_keypair();
        let (ct, ss_enc) = encapsulate(&pk);
        let ss_dec = decapsulate(&sk, &ct);
        
        assert_eq!(ss_enc.0.as_bytes(), ss_dec.0.as_bytes());
    }
}
