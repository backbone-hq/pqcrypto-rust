//! NTT backend for ML-KEM.
//!
//! ML-KEM uses the portable ("soft") implementation as its sole backend.
//! (An AVX2 backend behind a `simd` feature was evaluated and removed for
//! performance — see `docs/simd-constant-time-audit-2026.md`.)

use crate::params::N;

/// Always available portable implementation.
pub(crate) mod soft;

/// Forward NTT transform.
pub(crate) fn ntt(r: &mut [i16; N]) {
    soft::ntt(r)
}

/// Inverse NTT transform.
pub(crate) fn invntt(r: &mut [i16; N]) {
    soft::invntt(r)
}

/// Pointwise polynomial multiplication.
pub(crate) fn poly_basemul(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    soft::poly_basemul(r, a, b)
}
