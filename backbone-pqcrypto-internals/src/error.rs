//! Shared error types and traits for the pqcrypto workspace.
//!
//! This module provides a common error foundation that all pqcrypto crates
//! can build upon, enabling uniform error handling across algorithms.

use core::fmt;

#[cfg(feature = "std")]
extern crate std;

/// Core error kinds shared across most pqcrypto algorithms.
///
/// This enum captures the error variants that appear in multiple crates,
/// allowing callers to match on common failure modes without knowing
/// the specific algorithm crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PqcErrorKind {
    /// The provided public key has an invalid length.
    InvalidKeyLength,
    /// The provided secret key has an invalid length.
    InvalidSecretKeyLength,
    /// The provided ciphertext has an invalid length (KEMs).
    InvalidCiphertextLength,
    /// The provided signature has an invalid length (signatures).
    InvalidSignatureLength,
    /// The provided seed has an invalid length.
    InvalidSeedLength,
    /// The provided context is too long (FIPS 204/205 signatures).
    InvalidContextLength,
    /// The provided message is too long (ML-DSA).
    InvalidMessageLength,
    /// Random number generation failed (getrandom unavailable).
    RngFailure,
    /// Decapsulation failed due to re-encryption mismatch (KEMs).
    DecapsulationFailed,
    /// Signature verification failed (signatures).
    InvalidSignature,
    /// Signing failed due to internal rejection sampling exhaustion (signatures).
    SigningFailed,
    /// Polynomial not invertible during key generation (NTRU variants).
    NotInvertible,
    /// Key generation failed (McEliece).
    KeygenFailed,
    /// Invalid public key encoding/contents (ML-KEM).
    InvalidPublicKey,
    /// Invalid secret key contents (ML-KEM).
    InvalidSecretKey,
}

/// Trait for converting crate-specific errors to/from the common `PqcErrorKind`.
///
/// Implement this trait on your crate's `Error` enum to enable interoperability
/// with code that wants to handle pqcrypto errors generically.
pub trait PqcError: fmt::Debug + fmt::Display + PartialEq + Eq + Send + Sync + 'static {
    /// Convert this error to the most specific matching `PqcErrorKind`.
    ///
    /// Returns `None` if the error has no corresponding common kind
    /// (i.e., it's an algorithm-specific error not in the shared taxonomy).
    fn to_kind(&self) -> Option<PqcErrorKind>;
}

/// Convenience macro to implement `PqcError` for a crate's error enum.
///
/// Usage:
/// ```rust
/// use backbone_pqcrypto_internals::{impl_pqc_error, error::{PqcError, PqcErrorKind}};
///
/// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// pub enum MyError {
///     InvalidKeyLength,
///     InvalidSecretKeyLength,
///     RngFailure,
///     CustomError,
/// }
///
/// impl std::fmt::Display for MyError {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         match self {
///             MyError::InvalidKeyLength => write!(f, "invalid key length"),
///             MyError::InvalidSecretKeyLength => write!(f, "invalid secret key length"),
///             MyError::RngFailure => write!(f, "rng failure"),
///             MyError::CustomError => write!(f, "custom error"),
///         }
///     }
/// }
///
/// impl_pqc_error! {
///     MyError,
///     InvalidKeyLength => PqcErrorKind::InvalidKeyLength,
///     InvalidSecretKeyLength => PqcErrorKind::InvalidSecretKeyLength,
///     RngFailure => PqcErrorKind::RngFailure,
///     // CustomError has no mapping -> returns None
/// }
/// ```
#[macro_export]
macro_rules! impl_pqc_error {
    ($error_type:ty, $($variant:ident => $kind:path $(,)?),*) => {
        impl $crate::error::PqcError for $error_type {
            fn to_kind(&self) -> Option<$crate::error::PqcErrorKind> {
                match self {
                    $( <$error_type>::$variant => Some($kind), )*
                    _ => None,
                }
            }


        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestError {
        InvalidKeyLength,
        RngFailure,
        CustomError,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                TestError::InvalidKeyLength => write!(f, "invalid key length"),
                TestError::RngFailure => write!(f, "rng failure"),
                TestError::CustomError => write!(f, "custom error"),
            }
        }
    }

    impl_pqc_error! {
        TestError,
        InvalidKeyLength => PqcErrorKind::InvalidKeyLength,
        RngFailure => PqcErrorKind::RngFailure,
    }

    #[test]
    fn test_to_kind() {
        assert_eq!(
            TestError::InvalidKeyLength.to_kind(),
            Some(PqcErrorKind::InvalidKeyLength)
        );
        assert_eq!(
            TestError::RngFailure.to_kind(),
            Some(PqcErrorKind::RngFailure)
        );
        assert_eq!(TestError::CustomError.to_kind(), None);
    }
}
