//! NTRU LPRime error types.

use core::fmt;

use pqcrypto_utils::{error::PqcErrorKind, impl_pqc_error};

/// Errors that can occur during NTRUPLR key generation, encapsulation, or decapsulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Public key has wrong length.
    InvalidKeyLength,
    /// Secret key has wrong length.
    InvalidSecretKeyLength,
    /// Ciphertext has wrong length.
    InvalidCiphertextLength,
    /// Decapsulation failed (re-encryption mismatch).
    DecapsulationFailed,
    /// Polynomial not invertible during key generation.
    NotInvertible,
    /// Random number generation failed.
    RngFailure,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKeyLength => write!(f, "invalid public key length"),
            Error::InvalidSecretKeyLength => write!(f, "invalid secret key length"),
            Error::InvalidCiphertextLength => write!(f, "invalid ciphertext length"),
            Error::DecapsulationFailed => write!(f, "decapsulation failed"),
            Error::NotInvertible => write!(f, "polynomial not invertible"),
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
    DecapsulationFailed => PqcErrorKind::DecapsulationFailed,
    NotInvertible => PqcErrorKind::NotInvertible,
    RngFailure => PqcErrorKind::RngFailure,
}
