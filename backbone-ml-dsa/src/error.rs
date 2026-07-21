//! ML-DSA error types.

use core::fmt;

use backbone_pqcrypto_internals::{error::PqcErrorKind, impl_pqc_error};

/// ML-DSA-specific errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Signature verification failed: the signature does not match the message and public key.
    InvalidSignature,
    /// Signing failed due to an internal condition (e.g. rejection sampling limit exceeded).
    SigningFailed,
    /// RNG failure (getrandom failure).
    RngFailure,
    /// The public key has an invalid length.
    InvalidKeyLength,
    /// The secret key has an invalid length.
    InvalidSecretKeyLength,
    /// The signature has an invalid length.
    InvalidSignatureLength,
    /// The supplied seed has an invalid length.
    InvalidSeedLength,
    /// The supplied context is too long for the FIPS domain separator.
    InvalidContextLength,
    /// The message length exceeds the maximum allowed.
    InvalidMessageLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::SigningFailed => write!(f, "signing failed (rejection sampling exhausted)"),
            Error::RngFailure => write!(f, "random number generation failed"),
            Error::InvalidKeyLength => write!(f, "invalid public key length"),
            Error::InvalidSecretKeyLength => write!(f, "invalid secret key length"),
            Error::InvalidSignatureLength => write!(f, "invalid signature length"),
            Error::InvalidSeedLength => write!(f, "invalid seed length"),
            Error::InvalidContextLength => write!(f, "invalid context length"),
            Error::InvalidMessageLength => write!(f, "invalid message length"),
        }
    }
}

#[cfg(feature = "std")]
impl core::error::Error for Error {}

impl_pqc_error! {
    Error,
    InvalidSignature => PqcErrorKind::InvalidSignature,
    SigningFailed => PqcErrorKind::SigningFailed,
    RngFailure => PqcErrorKind::RngFailure,
    InvalidKeyLength => PqcErrorKind::InvalidKeyLength,
    InvalidSecretKeyLength => PqcErrorKind::InvalidSecretKeyLength,
    InvalidSignatureLength => PqcErrorKind::InvalidSignatureLength,
    InvalidSeedLength => PqcErrorKind::InvalidSeedLength,
    InvalidContextLength => PqcErrorKind::InvalidContextLength,
    InvalidMessageLength => PqcErrorKind::InvalidMessageLength,
}
