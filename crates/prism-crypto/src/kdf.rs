use hkdf::Hkdf;
use sha2::Sha256;
use crate::errors::CryptoError;

pub struct DerivedKeys {
    pub encryption_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub blinding_factor: [u8; 32],
}

pub fn try_hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>, CryptoError> {
    if output_len > 255 * 32 {
        return Err(CryptoError::KdfError);
    }
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm).map_err(|_| CryptoError::KdfError)?;
    Ok(okm)
}

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    try_hkdf_sha256(ikm, salt, info, output_len).expect("HKDF expand output_len exceeds 255*32 bytes limit")
}

pub fn derive_keys(shared_secret: &[u8], info: &[u8]) -> Result<DerivedKeys, CryptoError> {
    let mut okm = [0u8; 96];
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    hk.expand(info, &mut okm).map_err(|_| CryptoError::KdfError)?;
    
    let mut encryption_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    let mut blinding_factor = [0u8; 32];
    
    encryption_key.copy_from_slice(&okm[0..32]);
    mac_key.copy_from_slice(&okm[32..64]);
    blinding_factor.copy_from_slice(&okm[64..96]);
    
    Ok(DerivedKeys {
        encryption_key,
        mac_key,
        blinding_factor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf() {
        let ikm = b"some shared secret";
        let out = hkdf_sha256(ikm, b"salt", b"info", 32);
        assert_eq!(out.len(), 32);
        
        let out2 = hkdf_sha256(ikm, b"salt", b"info", 32);
        assert_eq!(out, out2);
        
        let derived = derive_keys(ikm, b"info").unwrap();
        assert_ne!(derived.encryption_key, derived.mac_key);
    }
}
