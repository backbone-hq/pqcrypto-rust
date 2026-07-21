//! NTT backend dispatch for ML-KEM.
//!
//! When compiled with `features = ["simd"]` and the target supports AVX2
//! (e.g. via `-C target-cpu=native`), the AVX2 backend is used.
//! Otherwise, the portable ("soft") implementation is the sole backend.

use crate::params::N;

/// Always available portable implementation.
pub(crate) mod soft;

/// AVX2 backend — only compiled when `simd` feature is enabled AND the
/// target has AVX2 (via `cfg(target_feature = "avx2")`).
#[cfg(all(feature = "simd", target_feature = "avx2"))]
pub(crate) mod avx2;

/// Forward NTT transform.
pub(crate) fn ntt(r: &mut [i16; N]) {
    #[cfg(all(feature = "simd", target_feature = "avx2"))]
    return avx2::ntt(r);
    #[cfg(not(all(feature = "simd", target_feature = "avx2")))]
    soft::ntt(r)
}

/// Inverse NTT transform.
pub(crate) fn invntt(r: &mut [i16; N]) {
    #[cfg(all(feature = "simd", target_feature = "avx2"))]
    return avx2::invntt(r);
    #[cfg(not(all(feature = "simd", target_feature = "avx2")))]
    soft::invntt(r)
}

/// Pointwise polynomial multiplication.
pub(crate) fn poly_basemul(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    #[cfg(all(feature = "simd", target_feature = "avx2"))]
    return avx2::poly_basemul(r, a, b);
    #[cfg(not(all(feature = "simd", target_feature = "avx2")))]
    soft::poly_basemul(r, a, b)
}
