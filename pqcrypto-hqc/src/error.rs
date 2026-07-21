//! HQC error types.

use core::fmt;

use pqcrypto_utils::{error::PqcErrorKind, impl_pqc_error};

/// Errors that can occur during HQC key generation, encapsulation, or decapsulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Public key has wrong length.
    InvalidKeyLength,
    /// Secret key has wrong length.
    InvalidSecretKeyLength,
    /// Ciphertext has wrong length.
    InvalidCiphertextLength,
    /// Seed has wrong length.
    InvalidSeedLength,
    /// Decapsulation failed (re-encryption mismatch).
    DecapsulationFailed,
    /// Random number generation failed.
    RngFailure,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKeyLength => write!(f, "invalid public key length"),
            Error::InvalidSecretKeyLength => write!(f, "invalid secret key length"),
            Error::InvalidCiphertextLength => write!(f, "invalid ciphertext length"),
            Error::InvalidSeedLength => write!(f, "invalid seed length"),
            Error::DecapsulationFailed => write!(f, "decapsulation failed"),
            Error::RngFailure => write!(f, "random number generation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl core::error::Error for Error {}

impl_pqc_error! {
    Error,
    InvalidKeyLength => PqcErrorKind::InvalidKeyLength,
    InvalidSecretKeyLength => PqcErrorKind::InvalidSecretKeyLength,
    InvalidCiphertextLength => PqcErrorKind::InvalidCiphertextLength,
    InvalidSeedLength => PqcErrorKind::InvalidSeedLength,
    DecapsulationFailed => PqcErrorKind::DecapsulationFailed,
    RngFailure => PqcErrorKind::RngFailure,
}
