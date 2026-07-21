//! Shared utilities for the pqcrypto workspace.
//!
//! Provides KAT test vector parsing and shared helpers.
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
/// Karatsuba polynomial multiplication for NTRU Prime and related schemes.
pub mod karatsuba;
#[cfg(feature = "std")]
pub mod kat;
/// Secret-memory wrappers that zeroize on drop.
pub mod secret;
/// Recursive tree encoding utilities for KAT test vector generation.
pub mod tree_encode;
