//! Shared utilities for the pqcrypto workspace.
//!
//! Free functions in each variant module are the canonical API.

#![no_std]
#![deny(missing_docs)]

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
#[doc(hidden)]
pub mod nist_seed_expander;
#[doc(hidden)]
/// NTRU Prime ring arithmetic (Rq/R3 polynomials) shared by the sntrup and ntruplr crates.
pub mod ntrup;
/// Hash algorithms for HashML-DSA / HashSLH-DSA pre-hash mode.
pub mod oid;
/// Secret-memory wrappers that zeroize on drop.
pub mod secret;
/// Deterministic test fixtures (e.g. xorshift PRNG) shared across suites.
pub mod testutil;
#[doc(hidden)]
/// Recursive tree encoding utilities for KAT test vector generation.
pub mod tree_encode;
