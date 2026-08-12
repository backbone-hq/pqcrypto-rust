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

/// Deterministic xorshift64 PRNG for differential-test inputs — the shared
/// workspace test RNG (see `backbone_pqcrypto_internals::testutil`).
#[cfg(test)]
#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
fn random_poly(rng: &mut backbone_pqcrypto_internals::testutil::XorShift) -> Poly {
    let mut p = Poly::new();
    for v in p.coeffs.iter_mut() {
        *v = (rng.next_u64() % crate::field::Q as u64) as i32;
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use backbone_pqcrypto_internals::testutil::XorShift;

    /// The dispatch must agree with the always-compiled soft backend in
    /// both simd-on and simd-off builds (simd-off: verifies wiring;
    /// simd-on: exercises the AVX2 backend — in that case this is the
    /// AVX2-vs-soft differential).
    #[test]
    fn ntt_dispatch_matches_soft_random() {
        let mut rng = XorShift::from_seed(0x9E37_79B9_7F4A_7C15);
        for _ in 0..32 {
            let mut a_soft = random_poly(&mut rng);
            let mut a_active = a_soft.clone();
            soft::ntt(&mut a_soft);
            ntt(&mut a_active);
            for i in 0..256 {
                assert_eq!(a_soft.coeffs[i], a_active.coeffs[i], "ntt mismatch at {i}");
            }
        }
    }

    #[test]
    fn inv_ntt_dispatch_matches_soft_random() {
        let mut rng = XorShift::from_seed(0xD1B5_4A32_D192_ED03);
        for _ in 0..32 {
            let mut a = random_poly(&mut rng);
            ntt(&mut a);
            let mut a_soft = a.clone();
            let mut a_active = a;
            soft::inv_ntt(&mut a_soft);
            inv_ntt(&mut a_active);
            for i in 0..256 {
                assert_eq!(
                    a_soft.coeffs[i], a_active.coeffs[i],
                    "inv_ntt mismatch at {i}"
                );
            }
        }
    }

    #[test]
    fn ntt_mul_dispatch_matches_soft_random() {
        let mut rng = XorShift::from_seed(0xF0E1_D2C3_B4A5_9687);
        for _ in 0..32 {
            let a = random_poly(&mut rng);
            let b = random_poly(&mut rng);
            let mut c_soft = Poly::new();
            let mut c_active = Poly::new();
            soft::ntt_mul(&a, &b, &mut c_soft);
            ntt_mul(&a, &b, &mut c_active);
            for i in 0..256 {
                assert_eq!(
                    c_soft.coeffs[i], c_active.coeffs[i],
                    "ntt_mul mismatch at {i}"
                );
            }
        }
    }
}
