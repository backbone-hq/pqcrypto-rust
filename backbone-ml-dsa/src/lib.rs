//! ML-DSA (FIPS 204): Module-Lattice-Based Digital Signature Standard.
#![no_std]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub use backbone_pqcrypto_internals::oid::HashAlgorithm;
pub use rand_core;
pub(crate) mod backends;
/// ML-DSA error types.
pub mod error;
pub(crate) mod field;
pub(crate) mod macros;
pub(crate) mod matrix;
/// ML-DSA-44 variant (parameter set).
pub mod mldsa44;
/// ML-DSA-65 variant (parameter set).
pub mod mldsa65;
/// ML-DSA-87 variant (parameter set).
pub mod mldsa87;
pub(crate) mod ntt;
/// ML-DSA parameter sets.
pub mod params;
pub(crate) mod poly;
pub(crate) mod sampling;
pub(crate) mod sign;
