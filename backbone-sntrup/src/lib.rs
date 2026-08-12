//! Streamlined NTRU Prime implementation
#![no_std]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub use rand_core;
pub mod error;
#[cfg(test)]
mod kats;
pub(crate) mod kem;
pub(crate) mod macros;
pub mod params;
pub(crate) mod poly;
pub mod sntrup1013;
pub mod sntrup1277;
pub mod sntrup653;
pub mod sntrup761;
pub mod sntrup857;
pub mod sntrup953;
#[cfg(test)]
mod tests;
