//! NTT backend dispatch for ML-DSA.
//!
//! When compiled with `features = ["simd"]` and the target supports AVX2
//! (e.g. via `-C target-cpu=native`), the AVX2 backend is used.
//! Otherwise, the portable ("soft") implementation is the sole backend.

use crate::poly::Poly;

/// Always available portable implementation.
pub(crate) mod soft;

/// AVX2 backend — only compiled when `simd` feature is enabled AND the
/// target has AVX2 (via `cfg(target_feature = "avx2")`).
#[cfg(all(feature = "simd", target_feature = "avx2"))]
pub(crate) mod avx2;

/// Forward NTT transform.
pub(crate) fn ntt(p: &mut Poly) {
    #[cfg(all(feature = "simd", target_feature = "avx2"))]
    return avx2::ntt(p);
    #[cfg(not(all(feature = "simd", target_feature = "avx2")))]
    soft::ntt(p)
}

/// Inverse NTT transform.
pub(crate) fn inv_ntt(p: &mut Poly) {
    #[cfg(all(feature = "simd", target_feature = "avx2"))]
    return avx2::inv_ntt(p);
    #[cfg(not(all(feature = "simd", target_feature = "avx2")))]
    soft::inv_ntt(p)
}

/// Pointwise multiplication in NTT domain.
pub(crate) fn ntt_mul(a: &Poly, b: &Poly, c: &mut Poly) {
    #[cfg(all(feature = "simd", target_feature = "avx2"))]
    return avx2::ntt_mul(a, b, c);
    #[cfg(not(all(feature = "simd", target_feature = "avx2")))]
    soft::ntt_mul(a, b, c)
}
