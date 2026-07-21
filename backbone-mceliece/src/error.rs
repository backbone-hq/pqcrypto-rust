//! McEliece KEM error types.

use core::fmt;

use backbone_pqcrypto_internals::{error::PqcErrorKind, impl_pqc_error};

/// McEliece KEM errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Key generation failed (e.g. irreducible polynomial not found).
    KeygenFailed,
    /// Public key has wrong length.
    InvalidKeyLength,
    /// Secret key has wrong length.
    InvalidSecretKeyLength,
    /// Ciphertext has wrong length.
    InvalidCiphertextLength,
    /// Decapsulation failed (re-encryption mismatch).
    DecapsulationFailed,
    /// Random number generation failed.
    RngFailure,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::KeygenFailed => write!(f, "key generation failed"),
            Error::InvalidKeyLength => write!(f, "invalid public key length"),
            Error::InvalidSecretKeyLength => write!(f, "invalid secret key length"),
            Error::InvalidCiphertextLength => write!(f, "invalid ciphertext length"),
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
    DecapsulationFailed => PqcErrorKind::DecapsulationFailed,
    KeygenFailed => PqcErrorKind::KeygenFailed,
    RngFailure => PqcErrorKind::RngFailure,
}
