//! SPHINCS+ (FIPS 205) implementation: Stateless Hash-Based Digital Signature Standard
#![no_std]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;
pub(crate) mod address;
pub mod error;
pub(crate) mod fors;
pub(crate) mod hash;
pub(crate) mod macros;
pub(crate) mod merkle;
/// SPHINCS+ algorithm parameter definitions.
pub mod params;
pub mod sha2_128f;
pub mod sha2_128s;
pub mod sha2_192f;
pub mod sha2_192s;
pub mod sha2_256f;
pub mod sha2_256s;
pub mod shake128f;
pub mod shake128s;
pub mod shake192f;
pub mod shake192s;
pub mod shake256f;
pub mod shake256s;
/// SPHINCS+ signing and verification logic.
pub(crate) mod sign;
pub use crate::hash::Hash;
pub(crate) mod utils;
pub(crate) mod wots;
