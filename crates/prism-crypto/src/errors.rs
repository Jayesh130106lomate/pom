use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key exchange failed")]
    KeyExchangeFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("MAC verification failed")]
    MacVerificationFailed,
    #[error("KDF error")]
    KdfError,
}
