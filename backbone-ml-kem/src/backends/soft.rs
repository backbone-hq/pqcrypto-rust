//! Portable ("soft") NTT backend for ML-KEM.
//! Pure Rust implementation using Montgomery arithmetic with i16 coefficients.
//!
//! Always compiled — acts as the fallback on x86_64 when AVX2 is not
//! available at compile time, and as the sole backend on non-x86 targets.
//!
//! When `target_feature = "avx2"` is enabled, the AVX2 backend takes over
//! and these functions become unused (suppress dead_code).
#![cfg_attr(all(feature = "simd", target_feature = "avx2"), allow(dead_code))]

use crate::field::{barrett_reduce, montgomery_reduce};
use crate::ntt::ZETAS;
use crate::params::N;

/// Forward NTT transform.
pub(crate) fn ntt(r: &mut [i16; N]) {
    ntt_layers(r, 128, 1);
}

/// Run NTT layers starting from a given `len` and zeta index `k`.
pub(crate) fn ntt_layers(r: &mut [i16; N], mut len: usize, mut k: usize) {
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            let mut j = start;
            while j < start + len {
                let t = montgomery_reduce(i32::from(zeta) * i32::from(r[j + len]));
                r[j + len] = r[j].wrapping_sub(t);
                r[j] = r[j].wrapping_add(t);
                j += 1;
            }
            start = j + len;
        }
        len >>= 1;
    }
    for coeff in r.iter_mut() {
        *coeff = barrett_reduce(*coeff);
    }
}

/// Inverse NTT transform.
pub(crate) fn invntt(r: &mut [i16; N]) {
    let mut k = 127usize;
    let len = 2usize;
    invntt_layers(r, len, &mut k);
    for coeff in r.iter_mut() {
        *coeff = montgomery_reduce(i32::from(*coeff) * 1441);
    }
}

/// Run INV NTT layers starting from given len, updating zeta index k.
pub(crate) fn invntt_layers(r: &mut [i16; N], mut len: usize, k: &mut usize) {
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[*k];
            *k = (*k).wrapping_sub(1);
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_reduce({
                    i16::try_from(i32::from(t).wrapping_add(i32::from(r[j + len])))
                        .expect("sum of i16 values fits in i16")
                });
                r[j + len] = r[j + len].wrapping_sub(t);
                r[j + len] = montgomery_reduce(i32::from(zeta) * i32::from(r[j + len]));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
}

/// Multiply two NTT-domain polynomials pointwise.
pub(crate) fn poly_basemul(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    for i in 0..(N / 4) {
        let zeta = i32::from(ZETAS[64 + i]);
        let neg_zeta = i32::from(-ZETAS[64 + i]);

        let a0 = i32::from(a[4 * i]);
        let a1 = i32::from(a[4 * i + 1]);
        let b0 = i32::from(b[4 * i]);
        let b1 = i32::from(b[4 * i + 1]);
        let a2 = i32::from(a[4 * i + 2]);
        let a3 = i32::from(a[4 * i + 3]);
        let b2 = i32::from(b[4 * i + 2]);
        let b3 = i32::from(b[4 * i + 3]);

        let t = montgomery_reduce(a1 * b1);
        let t = montgomery_reduce(i32::from(t) * zeta);
        let t = t.wrapping_add(montgomery_reduce(a0 * b0));
        r[4 * i] = t;

        let t = montgomery_reduce(a0 * b1);
        let t = t.wrapping_add(montgomery_reduce(a1 * b0));
        r[4 * i + 1] = t;

        let t = montgomery_reduce(a3 * b3);
        let t = montgomery_reduce(i32::from(t) * neg_zeta);
        let t = t.wrapping_add(montgomery_reduce(a2 * b2));
        r[4 * i + 2] = t;

        let t = montgomery_reduce(a2 * b3);
        let t = t.wrapping_add(montgomery_reduce(a3 * b2));
        r[4 * i + 3] = t;
    }
}
