use thiserror::Error;

#[derive(Error, Debug)]
pub enum DirectoryError {
    #[error("Relay not found")]
    RelayNotFound,
    #[error("Path selection failed: {0}")]
    PathSelectionFailed(String),
}
