//! NTRU LPRime implementation
#![no_std]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub use rand_core;
pub(crate) mod aes_ctr;
pub mod error;
pub(crate) mod kem;
pub(crate) mod macros;
pub mod ntruplr1013;
pub mod ntruplr1277;
pub mod ntruplr653;
pub mod ntruplr761;
pub mod ntruplr857;
pub mod ntruplr953;
pub mod params;
pub(crate) mod poly;
