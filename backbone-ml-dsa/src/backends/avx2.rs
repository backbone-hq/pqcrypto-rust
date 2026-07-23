//! AVX2 (256-bit SIMD) NTT backend for ML-DSA (FIPS 204).
//!
//! Uses safe_arch for a safe-Rust AVX2 implementation.
//! Only compiled when the target has AVX2 (via `cfg(target_feature = "avx2")`).
//!
//! ML-DSA coefficients are i32 modulo Q = 8380417.  Montgomery reduction
//! operates on i64 intermediate values (product of two i32 coefficients).
//! This backend processes 4 butterfly pairs per AVX2 vector using
//! `_mm256_mul_epi32` for the widening multiply and decomposes each i64
//! result into low/high i32 halves for borrow-based reduction (same
//! technique as the ML-KEM i16 backend, scaled to 32-bit).

use safe_arch::*;

use crate::field::Q;
use crate::poly::Poly;

const QINV: i32 = 58728449;
const F: i32 = 41978;

#[inline(always)]
fn load_8_i32(slice: &[i32]) -> m256i {
    m256i::from(<[i32; 8]>::try_from(&slice[..8]).expect("load_8_i32: slice len >= 8"))
}

#[inline(always)]
fn store_8_i32(v: m256i, slice: &mut [i32]) {
    slice[..8].copy_from_slice(&<[i32; 8]>::from(v));
}

#[inline(always)]
fn splat_i32(v: i32) -> m256i {
    m256i::from([v; 8])
}

const EVEN_TO_LANES: [i32; 8] = [0, 4, 1, 4, 2, 4, 3, 4];
const ODD_TO_LANES: [i32; 8] = [4, 0, 4, 1, 4, 2, 4, 3];
const ODD_SHUFFLE: [i32; 8] = [1, 0, 3, 2, 5, 4, 7, 6];

#[inline]
fn montgomery_mul_vector(r: m256i, zeta: i32) -> m256i {
    let zeta_v = splat_i32(zeta);
    let q_v = splat_i32(Q);
    let qinv_v = splat_i32(QINV);
    let flip = splat_i32(i32::MIN);

    let prod_even = mul_i64_low_bits_m256i(r, zeta_v);
    let r_even_raw = montgomery_reduce_4x64(prod_even, q_v, qinv_v, flip);
    let even_ctrl = m256i::from(EVEN_TO_LANES);
    let r_even = shuffle_av_i32_all_m256i(r_even_raw, even_ctrl);

    let odd_shuffle = m256i::from(ODD_SHUFFLE);
    let r_shuf = shuffle_av_i32_all_m256i(r, odd_shuffle);
    let prod_odd = mul_i64_low_bits_m256i(r_shuf, zeta_v);
    let r_odd_raw = montgomery_reduce_4x64(prod_odd, q_v, qinv_v, flip);
    let odd_ctrl = m256i::from(ODD_TO_LANES);
    let r_odd = shuffle_av_i32_all_m256i(r_odd_raw, odd_ctrl);

    bitor_m256i(r_even, r_odd)
}

/// Montgomery-reduce 4 × i64 lanes from vpmuldq into 4 × i32.
///
/// Input `a` is the result of `mul_i64_low_bits_m256i`, packed as
///   [i64[0].lo, i64[0].hi, i64[1].lo, i64[1].hi,
///    i64[2].lo, i64[2].hi, i64[3].lo, i64[3].hi]
///
/// Returns an m256i where the low 4 i32 lanes are the reduced values.
/// The high 4 lanes are zeroed.
#[inline]
fn montgomery_reduce_4x64(a: m256i, q: m256i, qinv: m256i, flip: m256i) -> m256i {
    let extract_lo = m256i::from([0i32, 2, 4, 6, 0, 0, 0, 0]);
    let a_lo = shuffle_av_i32_all_m256i(a, extract_lo);

    let extract_hi = m256i::from([1i32, 3, 5, 7, 0, 0, 0, 0]);
    let a_hi = shuffle_av_i32_all_m256i(a, extract_hi);

    let t = mul_i32_keep_low_m256i(a_lo, qinv);

    let repack_t = m256i::from([0i32, 0, 1, 0, 2, 0, 3, 0]);
    let t_even = shuffle_av_i32_all_m256i(t, repack_t);
    let tq = mul_i64_low_bits_m256i(t_even, q);

    let tq_lo = shuffle_av_i32_all_m256i(tq, extract_lo);
    let tq_hi = shuffle_av_i32_all_m256i(tq, extract_hi);

    let borrow = cmp_gt_mask_i32_m256i(tq_lo ^ flip, a_lo ^ flip);

    add_i32_m256i(sub_i32_m256i(a_hi, tq_hi), borrow)
}

pub(crate) fn ntt(p: &mut Poly) {
    let coeffs = &mut *p.coeffs;
    let mut k = 0;
    let mut len = 128;

    while len >= 1 {
        for start in (0..256).step_by(2 * len) {
            k += 1;
            let zeta = super::soft::ZETAS[k];

            let mut j = start;
            while j + 8 <= start + len {
                let v0 = load_8_i32(&coeffs[j..]);
                let v1 = load_8_i32(&coeffs[j + len..]);

                let t = montgomery_mul_vector(v1, zeta);
                let new_v0 = add_i32_m256i(v0, t);
                let new_v1 = sub_i32_m256i(v0, t);

                store_8_i32(new_v0, &mut coeffs[j..]);
                store_8_i32(new_v1, &mut coeffs[j + len..]);
                j += 8;
            }

            while j < start + len {
                let t =
                    crate::field::montgomery_reduce(i64::from(coeffs[j + len]) * i64::from(zeta));
                coeffs[j + len] = coeffs[j].wrapping_sub(t);
                coeffs[j] = coeffs[j].wrapping_add(t);
                j += 1;
            }
        }
        len /= 2;
    }
}

pub(crate) fn inv_ntt(p: &mut Poly) {
    let coeffs = &mut *p.coeffs;
    let mut k = 256;
    let mut len = 1;

    while len <= 128 {
        for start in (0..256).step_by(2 * len) {
            k -= 1;
            let zeta_neg = (super::soft::ZETAS[k]).wrapping_neg();

            let mut j = start;
            while j + 8 <= start + len {
                let v0 = load_8_i32(&coeffs[j..]);
                let v1 = load_8_i32(&coeffs[j + len..]);

                let sum = add_i32_m256i(v0, v1);
                let diff = sub_i32_m256i(v0, v1);

                let t = montgomery_mul_vector(diff, zeta_neg);

                store_8_i32(sum, &mut coeffs[j..]);
                store_8_i32(t, &mut coeffs[j + len..]);
                j += 8;
            }

            while j < start + len {
                let a = coeffs[j];
                let b = coeffs[j + len];
                coeffs[j] = a.wrapping_add(b);
                coeffs[j + len] = crate::field::montgomery_reduce(
                    i64::from(a.wrapping_sub(b)) * i64::from(zeta_neg),
                );
                j += 1;
            }
        }
        len *= 2;
    }

    let mut j = 0;
    while j + 8 <= 256 {
        let v = load_8_i32(&coeffs[j..]);
        let result = montgomery_mul_vector(v, F);
        store_8_i32(result, &mut coeffs[j..]);
        j += 8;
    }
    while j < 256 {
        coeffs[j] = crate::field::montgomery_reduce(i64::from(coeffs[j]) * i64::from(F));
        j += 1;
    }
}

pub(crate) fn ntt_mul(a: &Poly, b: &Poly, c: &mut Poly) {
    let q_v = splat_i32(Q);
    let qinv_v = splat_i32(QINV);
    let flip = splat_i32(i32::MIN);
    let mut j = 0;
    while j + 8 <= 256 {
        let va = load_8_i32(&a.coeffs.as_ref()[j..]);
        let vb = load_8_i32(&b.coeffs.as_ref()[j..]);

        let prod_even = mul_i64_low_bits_m256i(va, vb);
        let r_even_raw = montgomery_reduce_4x64(prod_even, q_v, qinv_v, flip);
        let even_ctrl = m256i::from(EVEN_TO_LANES);
        let r_even = shuffle_av_i32_all_m256i(r_even_raw, even_ctrl);

        let odd_shuffle = m256i::from(ODD_SHUFFLE);
        let va_shuf = shuffle_av_i32_all_m256i(va, odd_shuffle);
        let vb_shuf = shuffle_av_i32_all_m256i(vb, odd_shuffle);
        let prod_odd = mul_i64_low_bits_m256i(va_shuf, vb_shuf);
        let r_odd_raw = montgomery_reduce_4x64(prod_odd, q_v, qinv_v, flip);
        let odd_ctrl = m256i::from(ODD_TO_LANES);
        let r_odd = shuffle_av_i32_all_m256i(r_odd_raw, odd_ctrl);

        let result = bitor_m256i(r_even, r_odd);
        store_8_i32(result, &mut c.coeffs.as_mut()[j..]);
        j += 8;
    }
    while j < 256 {
        c.coeffs[j] =
            crate::field::montgomery_reduce(i64::from(a.coeffs[j]) * i64::from(b.coeffs[j]));
        j += 1;
    }
}
