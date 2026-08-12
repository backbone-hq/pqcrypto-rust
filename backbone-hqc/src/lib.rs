//! HQC (Hamming Quasi-Cyclic) KEM implementation
//! NIST post-quantum cryptography standard (FIPS 207)
#![no_std]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub use rand_core;
pub(crate) mod codec;
pub mod error;
pub(crate) mod gf;
pub(crate) mod gf2x;
pub(crate) mod hqc;
pub mod hqc128;
pub mod hqc192;
pub mod hqc256;
pub(crate) mod kem;
pub(crate) mod macros;
pub mod params;
pub(crate) mod parsing;
pub(crate) mod reed_muller;
pub(crate) mod reed_solomon;
pub(crate) mod vector;
