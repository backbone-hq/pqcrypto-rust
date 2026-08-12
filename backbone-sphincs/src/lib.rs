//! SPHINCS+ (FIPS 205) implementation: Stateless Hash-Based Digital Signature Standard
//!
//! Public API via per-variant modules (shake128f, sha2_256f, etc.).

#![no_std]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub use backbone_pqcrypto_internals::oid::HashAlgorithm;
pub use rand_core;

pub(crate) mod sphincs;

pub mod error;
pub(crate) mod macros;
pub mod params;

/// SLH-DSA-SHA2-128f variant module.
pub mod sha2_128f;
/// SLH-DSA-SHA2-128s variant module.
pub mod sha2_128s;
/// SLH-DSA-SHA2-192f variant module.
pub mod sha2_192f;
/// SLH-DSA-SHA2-192s variant module.
pub mod sha2_192s;
/// SLH-DSA-SHA2-256f variant module.
pub mod sha2_256f;
/// SLH-DSA-SHA2-256s variant module.
pub mod sha2_256s;
/// SLH-DSA-SHAKE-128f variant module.
pub mod shake128f;
/// SLH-DSA-SHAKE-128s variant module.
pub mod shake128s;
/// SLH-DSA-SHAKE-192f variant module.
pub mod shake192f;
/// SLH-DSA-SHAKE-192s variant module.
pub mod shake192s;
/// SLH-DSA-SHAKE-256f variant module.
pub mod shake256f;
/// SLH-DSA-SHAKE-256s variant module.
pub mod shake256s;
