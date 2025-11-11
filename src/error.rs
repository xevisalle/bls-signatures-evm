use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid bytes")]
    InvalidBytes,
}
