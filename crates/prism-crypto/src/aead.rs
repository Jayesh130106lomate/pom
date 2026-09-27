use chacha20poly1305::{XChaCha20Poly1305, Key as ChaChaKey, XNonce, aead::{Aead, KeyInit, Payload}};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use crate::errors::CryptoError;

pub fn xchacha20_encrypt(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    let xnonce = XNonce::from_slice(nonce);
    
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    
    cipher.encrypt(xnonce, payload).map_err(|_| CryptoError::EncryptionFailed)
}

pub fn xchacha20_decrypt(key: &[u8; 32], nonce: &[u8; 24], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    let xnonce = XNonce::from_slice(nonce);
    
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    
    cipher.decrypt(xnonce, payload).map_err(|_| CryptoError::DecryptionFailed)
}

pub fn aes256gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
    let nonce = AesNonce::from_slice(nonce);
    
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    
    cipher.encrypt(nonce, payload).map_err(|_| CryptoError::EncryptionFailed)
}

pub fn aes256gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
    let nonce = AesNonce::from_slice(nonce);
    
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    
    cipher.decrypt(nonce, payload).map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xchacha20() {
        let key = [1u8; 32];
        let nonce = [2u8; 24];
        let pt = b"hello world";
        let aad = b"aad data";
        
        let ct = xchacha20_encrypt(&key, &nonce, pt, aad).unwrap();
        let dec = xchacha20_decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, dec.as_slice());
        
        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        assert!(xchacha20_decrypt(&key, &nonce, &tampered, aad).is_err());
    }

    #[test]
    fn test_aes256gcm() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let pt = b"hello world";
        let aad = b"aad data";
        
        let ct = aes256gcm_encrypt(&key, &nonce, pt, aad).unwrap();
        let dec = aes256gcm_decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, dec.as_slice());
        
        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        assert!(aes256gcm_decrypt(&key, &nonce, &tampered, aad).is_err());
    }
}
