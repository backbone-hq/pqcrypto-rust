//! GF(2^x) polynomial multiplication
//! Uses Karatsuba multiplication with base_mul for 64×64 → 128 carryless multiply.
//!
//! When compiled with `features = ["simd"]` and `RUSTFLAGS="-C target-cpu=native"`,
//! the base multiplication uses a single `PCLMULQDQ` instruction via `safe_arch`
//! (~7 cycles) instead of the software LUT (~60 cycles).

use crate::params::Params;
use alloc::vec;

/// Software carryless multiply of two 64-bit values (result is 128 bits).
/// Uses a 16-entry LUT with 4-bit nibble stepping.
#[cfg(not(all(feature = "simd", target_feature = "pclmulqdq")))]
fn base_mul_fallback(a: u64, b: u64) -> (u64, u64) {
    let b_lo = b & 0x0FFFFFFFFFFFFFFF;

    let u0 = 0u64;
    let u1 = b_lo;
    let u2 = u1 << 1;
    let u3 = u2 ^ u1;
    let u4 = u2 << 1;
    let u5 = u4 ^ u1;
    let u6 = u3 << 1;
    let u7 = u6 ^ u1;
    let u8 = u4 << 1;
    let u9 = u8 ^ u1;
    let u10 = u5 << 1;
    let u11 = u10 ^ u1;
    let u12 = u6 << 1;
    let u13 = u12 ^ u1;
    let u14 = u7 << 1;
    let u15 = u14 ^ u1;
    let lut = [
        u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, u10, u11, u12, u13, u14, u15,
    ];

    let mut g = lut[(a & 0x0F) as usize];
    let mut l = g;
    let mut h = 0u64;

    let mut s = 4u64;
    while s < 64 {
        g = lut[((a >> s) & 0x0F) as usize];
        l ^= g << s;
        h ^= g >> (64 - s);
        s += 4;
    }

    for i in 0..4 {
        let mask = 0u64.wrapping_sub((b >> (60 + i)) & 1);
        l ^= (a << (60 + i)) & mask;
        h ^= (a >> (4 - i)) & mask;
    }

    (l, h)
}

/// 64×64 carryless multiply — uses PCLMULQDQ when compiled with simd + pclmulqdq.
#[cfg(all(feature = "simd", target_feature = "pclmulqdq"))]
#[inline]
fn base_mul(a: u64, b: u64) -> (u64, u64) {
    use safe_arch::{m128i, mul_i64_carryless_m128i};
    let p = m128i::from([i64::from_ne_bytes(a.to_ne_bytes()), 0i64]);
    let q = m128i::from([i64::from_ne_bytes(b.to_ne_bytes()), 0i64]);
    let r: m128i = mul_i64_carryless_m128i::<0>(p, q);
    let res: [i64; 2] = r.into();
    (
        u64::from_ne_bytes(res[0].to_ne_bytes()),
        u64::from_ne_bytes(res[1].to_ne_bytes()),
    )
}

/// 64×64 carryless multiply — software LUT fallback.
#[cfg(not(all(feature = "simd", target_feature = "pclmulqdq")))]
#[inline]
fn base_mul(a: u64, b: u64) -> (u64, u64) {
    base_mul_fallback(a, b)
}

/// Karatsuba multiplication of two polynomials.
/// Result `o` has 2*size limbs.
fn karatsuba(o: &mut [u64], a: &[u64], b: &[u64], size: usize) {
    if size == 1 {
        let (l, h) = base_mul(a[0], b[0]);
        o[0] = l;
        o[1] = h;
        return;
    }

    let size_h = size / 2;
    let size_l = size.div_ceil(2);

    let ah = &a[size_l..];
    let bh = &b[size_l..];

    let mut alh = vec![0u64; size_l];
    let mut blh = vec![0u64; size_l];
    let mut tmp1 = vec![0u64; 2 * size_l];
    let mut tmp2 = vec![0u64; 2 * size_l];

    karatsuba(o, a, b, size_l);

    karatsuba(&mut tmp2, ah, bh, size_h);

    for i in 0..size_h {
        alh[i] = a[i] ^ a[i + size_l];
        blh[i] = b[i] ^ b[i + size_l];
    }
    if size_h < size_l {
        alh[size_h] = a[size_h];
        blh[size_h] = b[size_h];
    }

    karatsuba(&mut tmp1, &alh, &blh, size_l);

    for i in 0..(2 * size_l) {
        tmp1[i] ^= o[i];
    }
    for i in 0..(2 * size_h) {
        tmp1[i] ^= tmp2[i];
    }
    for i in 0..(2 * size_l) {
        o[i + size_l] ^= tmp1[i];
    }
    for i in 0..(2 * size_h) {
        o[i + 2 * size_l] ^= tmp2[i];
    }
}

/// Reduce product modulo Xⁿ - 1.
fn reduce<P: Params>(o: &mut [u64], a: &[u64]) {
    let n = P::VEC_N_SIZE_64;
    let n_bits = P::N;
    let shift = n_bits & 0x3F;
    for i in 0..n {
        let r = a[i + n - 1] >> shift;
        let carry = a[i + n] << (64 - shift);
        o[i] = a[i] ^ r ^ carry;
    }
    o[n - 1] &= P::RED_MASK;
}

pub(crate) fn vect_mul<P: Params>(o: &mut [u64], v1: &[u64], v2: &[u64]) {
    let n = P::VEC_N_SIZE_64;
    let mut o_karat = vec![0u64; n << 1];
    karatsuba(&mut o_karat, v1, v2, n);
    reduce::<P>(o, &o_karat);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_mul_identity() {
        let (l, h) = base_mul(1, 1);
        assert_eq!(l, 1);
        assert_eq!(h, 0);
    }

    #[test]
    fn test_base_mul_simple() {
        let (l, h) = base_mul(2, 2);
        assert_eq!(l, 4);
        assert_eq!(h, 0);
    }

    #[test]
    fn test_base_mul_overflow() {
        let (l, h) = base_mul(0xFFFFFFFFFFFFFFFF, 1);
        assert_eq!(l, 0xFFFFFFFFFFFFFFFF);
        assert_eq!(h, 0);
    }
}
