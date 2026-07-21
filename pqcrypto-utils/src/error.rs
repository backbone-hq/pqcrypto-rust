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

    /// Attempt to construct this error from a `PqcErrorKind`.
    ///
    /// Returns `None` if the kind doesn't map to a variant in this error type.
    fn from_kind(kind: PqcErrorKind) -> Option<Self>
    where
        Self: Sized;
}

/// A boxed error type that can hold any pqcrypto error.
///
/// Useful when you need to return errors from multiple pqcrypto crates
/// through a single return type.
#[cfg(feature = "std")]
pub type BoxedPqcError = alloc::boxed::Box<dyn core::error::Error + Send + Sync>;

/// Extension trait for `Result` to add pqcrypto-specific error helpers.
pub trait PqcResultExt<T, E: PqcError> {
    /// Map the error to its `PqcErrorKind`, if one exists.
    fn kind(self) -> Result<T, Option<PqcErrorKind>>;

    /// Convert the error to a boxed `std::error::Error` (requires `std` feature).
    #[cfg(feature = "std")]
    fn boxed(self) -> Result<T, BoxedPqcError>
    where
        E: core::error::Error;
}

impl<T, E: PqcError> PqcResultExt<T, E> for Result<T, E> {
    fn kind(self) -> Result<T, Option<PqcErrorKind>> {
        self.map_err(|e| e.to_kind())
    }

    #[cfg(feature = "std")]
    fn boxed(self) -> Result<T, BoxedPqcError>
    where
        E: core::error::Error,
    {
        self.map_err(|e| {
            let boxed: alloc::boxed::Box<dyn core::error::Error + Send + Sync> =
                alloc::boxed::Box::new(e);
            boxed
        })
    }
}

/// Convenience macro to implement `PqcError` for a crate's error enum.
///
/// Usage:
/// ```rust
/// use pqcrypto_utils::{impl_pqc_error, error::{PqcError, PqcErrorKind}};
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

            fn from_kind(kind: $crate::error::PqcErrorKind) -> Option<Self> {
                match kind {
                    $( $kind => Some(<$error_type>::$variant), )*
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

    #[test]
    fn test_from_kind() {
        assert_eq!(
            TestError::from_kind(PqcErrorKind::InvalidKeyLength),
            Some(TestError::InvalidKeyLength)
        );
        assert_eq!(
            TestError::from_kind(PqcErrorKind::RngFailure),
            Some(TestError::RngFailure)
        );
        assert_eq!(
            TestError::from_kind(PqcErrorKind::InvalidSecretKeyLength),
            None
        );
    }

    #[test]
    fn test_result_ext() {
        let ok: Result<(), TestError> = Ok(());
        let err: Result<(), TestError> = Err(TestError::RngFailure);

        assert!(ok.kind().is_ok());
        assert_eq!(err.kind(), Err(Some(PqcErrorKind::RngFailure)));

        let err2: Result<(), TestError> = Err(TestError::CustomError);
        assert_eq!(err2.kind(), Err(None));
    }
}
