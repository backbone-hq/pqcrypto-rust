//! Pure Rust implementations of McEliece KEM variants
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
pub(crate) mod common;
pub(crate) mod core_fft;
pub(crate) mod decode;
pub mod error;
pub(crate) mod gf;
#[macro_use]
pub(crate) mod macros;
pub(crate) mod fft_tables;
pub mod params;
pub(crate) mod sort;
pub(crate) mod vec_ops;

/// McEliece 348864 parameter set (12-bit field, 3488-bit code, 64 errors).
pub mod mceliece348864;
/// McEliece 348864f parameter set (12-bit field, 3488-bit code, 64 errors, fast variant).
pub mod mceliece348864f;
/// McEliece 460896 parameter set (13-bit field, 4608-bit code, 96 errors).
pub mod mceliece460896;
/// McEliece 460896f parameter set (13-bit field, 4608-bit code, 96 errors, fast variant).
pub mod mceliece460896f;
/// McEliece 6688128 parameter set (13-bit field, 6688-bit code, 128 errors).
pub mod mceliece6688128;
/// McEliece 6688128f parameter set (13-bit field, 6688-bit code, 128 errors, fast variant).
pub mod mceliece6688128f;
/// McEliece 6960119 parameter set (13-bit field, 6960-bit code, 119 errors).
pub mod mceliece6960119;
/// McEliece 6960119f parameter set (13-bit field, 6960-bit code, 119 errors, fast variant).
pub mod mceliece6960119f;
/// McEliece 8192128 parameter set (13-bit field, 8192-bit code, 128 errors).
pub mod mceliece8192128;
/// McEliece 8192128f parameter set (13-bit field, 8192-bit code, 128 errors, fast variant).
pub mod mceliece8192128f;
