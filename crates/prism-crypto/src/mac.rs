use hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::errors::CryptoError;

type HmacSha256 = Hmac<Sha256>;

pub fn compute_mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

pub fn verify_mac(key: &[u8], data: &[u8], expected: &[u8; 32]) -> Result<(), CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.verify_slice(expected).map_err(|_| CryptoError::MacVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac() {
        let key = b"my secret key";
        let data = b"hello world";
        
        let mac = compute_mac(key, data);
        assert!(verify_mac(key, data, &mac).is_ok());
        
        let wrong_key = b"wrong key";
        assert!(verify_mac(wrong_key, data, &mac).is_err());
    }
}
