//! Streamlined NTRU Prime implementation
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
#![allow(rustdoc::broken_intra_doc_links)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;
pub mod error;
pub(crate) mod kem;
pub(crate) mod macros;
pub mod params;
pub(crate) mod poly;
pub mod sntrup653;
pub mod sntrup761;
pub mod sntrup857;
#[cfg(test)]
mod tests;
