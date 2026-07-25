//! Shared utilities for the pqcrypto workspace.
//!
//! The `traits` module was removed as part of simplifying the API.
//! Free functions in each variant module are the canonical API.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

/// Constant-time comparison and selection utilities (less-than, max, nonzero count).
pub mod ct;
/// Shared error types and traits for uniform error handling across crates.
pub mod error;
#[doc(hidden)]
/// Karatsuba polynomial multiplication for NTRU Prime and related schemes.
pub mod karatsuba;
#[cfg(feature = "std")]
#[doc(hidden)]
pub mod kat;
/// Hash algorithms for HashML-DSA / HashSLH-DSA pre-hash mode.
pub mod oid;
/// Secret-memory wrappers that zeroize on drop.
pub mod secret;
#[doc(hidden)]
/// Recursive tree encoding utilities for KAT test vector generation.
pub mod tree_encode;
