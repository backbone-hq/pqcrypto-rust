//! Karatsuba polynomial multiplication.
//!
//! Generic over polynomial coefficient storage (i64).  Used by both
//! Rq (Z/4591Z) and R3 (GF(3)) multiplication in `poly.rs`.
//!
//! ## Strategy
//!
//! 1. Convert the coefficient arrays to `i64` once.
//! 2. `karatsuba_mul` computes the full linear convolution (degree 2p-2)
//!    using Θ(n^(log₂ 3)) operations.
//! 3. `reduce_ring` applies the NTRU Prime ring law x^p = x + 1.
//! 4. Convert back to the target coefficient type.
//!
//! The base case below `KARATSUBA_THRESHOLD` (32) uses a straight schoolbook
//! loop without secret-dependent zero skips.

use crate::secret::SecretVec;

/// Below this size we fall back to schoolbook (quadratic but low constant).
const KARATSUBA_THRESHOLD: usize = 32;

///
/// `o` must have **at least `2 * n`** elements (zeroed automatically).
/// On return `o[0 .. 2*n-1]` contains the full linear convolution
/// (the product in the polynomial ring Z`[x]` before any ring reduction).
///
pub fn karatsuba_mul(o: &mut [i64], a: &[i64], b: &[i64], n: usize) {
    debug_assert!(
        o.len() >= 2 * n,
        "karatsuba_mul: output buffer too small (need {} elements, got {})",
        2 * n,
        o.len()
    );
    o.fill(0);
    if n <= KARATSUBA_THRESHOLD {
        schoolbook(o, a, b, n);
        return;
    }

    let n_lo = n.div_ceil(2);
    let n_hi = n - n_lo;

    let mut z2 = SecretVec::<i64>::new(2 * n_hi);
    let mut z1 = SecretVec::<i64>::new(2 * n_lo);

    karatsuba_mul(o, a, b, n_lo);

    karatsuba_mul(&mut z2, &a[n_lo..], &b[n_lo..], n_hi);

    let mut sum_a = SecretVec::<i64>::new(n_lo);
    let mut sum_b = SecretVec::<i64>::new(n_lo);
    for i in 0..n_hi {
        sum_a[i] = a[i] + a[n_lo + i];
        sum_b[i] = b[i] + b[n_lo + i];
    }
    if n_hi < n_lo {
        sum_a[n_hi] = a[n_hi];
        sum_b[n_hi] = b[n_hi];
    }

    karatsuba_mul(&mut z1, &sum_a, &sum_b, n_lo);

    for i in 0..(2 * n_lo) {
        z1[i] -= o[i];
    }
    for i in 0..(2 * n_hi) {
        z1[i] -= z2[i];
    }

    for i in 0..(2 * n_lo) {
        o[n_lo + i] += z1[i];
    }
    for i in 0..(2 * n_hi) {
        o[2 * n_lo + i] += z2[i];
    }
}

fn schoolbook(o: &mut [i64], a: &[i64], b: &[i64], n: usize) {
    for i in 0..n {
        let ai = a[i];
        for j in 0..n {
            o[i + j] += ai * b[j];
        }
    }
}

/// Apply the NTRU Prime ring reduction to the *full* product in `acc`.
///
/// The ring law  x^p = x + 1  means:
///   c_{p+t} · x^{p+t}   →   c_{p+t} · (x^{t+1} + x^{t})
///
/// `acc` must have at least `2 * p` elements.  The full product lives in
/// `acc[0 .. 2p-1]`.  After reduction, the first `p` coefficients hold the
/// canonical result in the ring.
pub fn reduce_ring(acc: &mut [i64], p: usize) {
    for t in 0..p - 1 {
        let val = acc[p + t];
        acc[t] += val;
        acc[t + 1] += val;
    }
}
