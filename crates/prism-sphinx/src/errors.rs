//! Error types for Sphinx packet operations.

use thiserror::Error;

/// Errors that can occur during Sphinx packet operations.
#[derive(Debug, Error)]
pub enum SphinxError {
    #[error("Invalid packet size: expected {expected}, got {got}")]
    InvalidPacketSize { expected: usize, got: usize },

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("MAC verification failed at hop {hop}")]
    MacVerificationFailed { hop: usize },

    #[error("Payload authentication failed: Poly1305 tag mismatch")]
    PayloadAuthenticationFailed,

    #[error("Replay detected: packet tag already seen")]
    ReplayDetected,

    #[error("Invalid routing info: {0}")]
    InvalidRoutingInfo(String),

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("Invalid epoch: expected {expected}, got {got}")]
    InvalidEpoch { expected: u64, got: u64 },

    #[error("Too many hops: maximum is {max}, requested {requested}")]
    TooManyHops { max: usize, requested: usize },

    #[error("Payload too large: maximum is {max}, got {got}")]
    PayloadTooLarge { max: usize, got: usize },

    #[error("Fragmentation error: {0}")]
    FragmentationError(String),

    #[error("Reassembly error: {0}")]
    ReassemblyError(String),

    #[error("Reassembly incomplete: have {have} of {total} fragments")]
    ReassemblyIncomplete { have: usize, total: usize },

    #[error("SURB error: {0}")]
    SurbError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Invalid fragment: {0}")]
    InvalidFragment(String),
}

impl From<prism_crypto::CryptoError> for SphinxError {
    fn from(e: prism_crypto::CryptoError) -> Self {
        SphinxError::CryptoError(e.to_string())
    }
}
