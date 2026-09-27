use thiserror::Error;

#[derive(Error, Debug)]
pub enum MixError {
    #[error("Failed to schedule packet")]
    SchedulingError,
    #[error("Pool error: {0}")]
    PoolError(String),
    #[error("Cover generation error: {0}")]
    CoverError(String),
}
