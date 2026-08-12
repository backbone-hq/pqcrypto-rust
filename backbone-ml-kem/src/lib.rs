//! ML-KEM (FIPS 203) implementation: Module-Lattice-Based Key Encapsulation Mechanism.
#![no_std]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub use rand_core;
pub(crate) mod backends;
pub mod error;
pub(crate) mod field;
pub(crate) mod kem;
pub(crate) mod macros;
pub mod mlkem1024;
pub mod mlkem512;
pub mod mlkem768;
pub(crate) mod ntt;
pub mod params;
pub(crate) mod poly;
pub(crate) mod sampling;

#[cfg(test)]
mod kats;
#[cfg(test)]
mod transcript;
