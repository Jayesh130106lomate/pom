use zeroize::Zeroize;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
    
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; 32],
}

impl PublicKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
    
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

impl From<PublicKey> for [u8; 32] {
    fn from(key: PublicKey) -> Self {
        key.bytes
    }
}

#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn new(secret: SecretKey, public: PublicKey) -> Self {
        Self { secret, public }
    }
}
