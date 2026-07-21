//! ML-DSA (FIPS 204) implementation
//! Module-Lattice-Based Digital Signature Standard
#![no_std]
// These casts are structurally necessary for ported reference implementations:
// Montgomery reduction, bit-packing, and modulus operations are mathematically
// proven to stay within range. try_from would add unwrap overhead in hot loops.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;
pub(crate) mod backends;
pub mod error;
pub(crate) mod field;
pub(crate) mod macros;
pub(crate) mod matrix;
pub mod mldsa44;
pub mod mldsa65;
pub mod mldsa87;
pub(crate) mod ntt;
pub mod params;
pub(crate) mod poly;
pub(crate) mod sampling;
pub(crate) mod sign;
