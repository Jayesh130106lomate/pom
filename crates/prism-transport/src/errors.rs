//! Transport error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Receive failed: {0}")]
    ReceiveFailed(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Bind failed: {0}")]
    BindFailed(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Timeout")]
    Timeout,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
