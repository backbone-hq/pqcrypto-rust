//! ML-KEM error types.

use core::fmt;

use pqcrypto_utils::{error::PqcErrorKind, impl_pqc_error};

/// Errors for ML-KEM operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Invalid key length.
    InvalidKeyLength,
    /// Invalid public key encoding.
    InvalidPublicKey,
    /// Invalid secret key length.
    InvalidSecretKeyLength,
    /// Invalid secret key contents.
    InvalidSecretKey,
    /// Invalid ciphertext length.
    InvalidCiphertextLength,
    /// RNG failure (system randomness unavailable).
    RngFailure,
    /// Decapsulation failed (re-encryption mismatch).
    DecapsulationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKeyLength => write!(f, "invalid public key length"),
            Error::InvalidPublicKey => write!(f, "invalid public key"),
            Error::InvalidSecretKeyLength => write!(f, "invalid secret key length"),
            Error::InvalidSecretKey => write!(f, "invalid secret key"),
            Error::InvalidCiphertextLength => write!(f, "invalid ciphertext length"),
            Error::RngFailure => write!(f, "random number generation failed"),
            Error::DecapsulationFailed => write!(f, "decapsulation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl core::error::Error for Error {}

impl_pqc_error! {
    Error,
    InvalidKeyLength => PqcErrorKind::InvalidKeyLength,
    InvalidPublicKey => PqcErrorKind::InvalidPublicKey,
    InvalidSecretKeyLength => PqcErrorKind::InvalidSecretKeyLength,
    InvalidSecretKey => PqcErrorKind::InvalidSecretKey,
    InvalidCiphertextLength => PqcErrorKind::InvalidCiphertextLength,
    RngFailure => PqcErrorKind::RngFailure,
    DecapsulationFailed => PqcErrorKind::DecapsulationFailed,
}
