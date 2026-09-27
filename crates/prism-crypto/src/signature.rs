use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use crate::errors::CryptoError;

pub fn generate_signing_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn sign(key: &SigningKey, message: &[u8]) -> Signature {
    key.sign(message)
}

pub fn verify(key: &VerifyingKey, message: &[u8], sig: &Signature) -> Result<(), CryptoError> {
    key.verify(message, sig).map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature() {
        let (sk, vk) = generate_signing_keypair();
        let msg = b"hello world";
        
        let sig = sign(&sk, msg);
        assert!(verify(&vk, msg, &sig).is_ok());
        
        let wrong_msg = b"hello there";
        assert!(verify(&vk, wrong_msg, &sig).is_err());
    }
}
