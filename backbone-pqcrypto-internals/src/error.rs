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
    /// Internal invariant failure (should be unreachable).
    Internal,
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
/// use backbone_pqcrypto_internals::{impl_pqc_error, error::PqcErrorKind};
///
/// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// pub enum MyError { InvalidKeyLength, RngFailure }
///
/// impl core::fmt::Display for MyError {
///     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
///         write!(f, "{self:?}")
///     }
/// }
///
/// impl_pqc_error! {
///     MyError,
///     InvalidKeyLength => PqcErrorKind::InvalidKeyLength,
///     RngFailure => PqcErrorKind::RngFailure,
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

/// Convenience macro to define a crate's public `Error` enum together with its
/// `Display` impl, its `core::error::Error` impl (behind the `std` feature),
/// and its `PqcError`/`PqcErrorKind` mapping in one place.
///
/// Every variant maps to the same-named `PqcErrorKind`; if a variant has no
/// corresponding kind, add one to the taxonomy in this module.
#[macro_export]
macro_rules! define_error {
    (
        $(#[$enum_doc:meta])*
        $error_type:ident;
        $(
            $(#[$variant_doc:meta])*
            $variant:ident => $msg:literal
        ),+ $(,)?
    ) => {
        $(#[$enum_doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $error_type {
            $(
                $(#[$variant_doc])*
                $variant,
            )+
        }

        impl ::core::fmt::Display for $error_type {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    $(
                        $error_type::$variant => ::core::write!(f, $msg),
                    )+
                }
            }
        }

        #[cfg(feature = "std")]
        impl ::core::error::Error for $error_type {}

        $crate::impl_pqc_error! {
            $error_type,
            $( $variant => $crate::error::PqcErrorKind::$variant, )+
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
