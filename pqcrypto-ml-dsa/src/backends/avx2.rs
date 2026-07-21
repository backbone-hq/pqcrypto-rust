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

const QINV: i32 = 58728449; // q⁻¹ mod 2³²
const F: i32 = 41978; // scaling factor for inv_ntt

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

// VPERMD control vectors (constant — built at compile time via m256i::from)
const EVEN_TO_LANES: [i32; 8] = [0, 4, 1, 4, 2, 4, 3, 4];
//   pos 0,2,4,6 get results 0,1,2,3; odd lanes get 0 (src[4] = first zero lane)
const ODD_TO_LANES: [i32; 8] = [4, 0, 4, 1, 4, 2, 4, 3];
//   pos 1,3,5,7 get results 0,1,2,3; even lanes get 0 (src[4] = first zero lane)
const ODD_SHUFFLE: [i32; 8] = [1, 0, 3, 2, 5, 4, 7, 6];
//   swap adjacent pairs: odd → even, even → odd

#[inline]
fn montgomery_mul_vector(r: m256i, zeta: i32) -> m256i {
    let zeta_v = splat_i32(zeta);
    let q_v = splat_i32(Q);
    let qinv_v = splat_i32(QINV);
    let flip = splat_i32(i32::MIN);

    // --- Even-indexed lanes (0, 2, 4, 6) ---
    let prod_even = mul_i64_low_bits_m256i(r, zeta_v);
    let r_even_raw = montgomery_reduce_4x64(prod_even, q_v, qinv_v, flip);
    // r_even_raw = [r0, r2, r4, r6, 0, 0, 0, 0]
    // Place at positions 0, 2, 4, 6
    let even_ctrl = m256i::from(EVEN_TO_LANES);
    let r_even = shuffle_av_i32_all_m256i(r_even_raw, even_ctrl);
    // r_even = [r0, 0, r2, 0, r4, 0, r6, 0]

    // --- Odd-indexed lanes (1, 3, 5, 7) — shuffle to even positions ---
    let odd_shuffle = m256i::from(ODD_SHUFFLE);
    let r_shuf = shuffle_av_i32_all_m256i(r, odd_shuffle);
    let prod_odd = mul_i64_low_bits_m256i(r_shuf, zeta_v);
    let r_odd_raw = montgomery_reduce_4x64(prod_odd, q_v, qinv_v, flip);
    // r_odd_raw = [r1, r3, r5, r7, 0, 0, 0, 0]
    // Place at positions 1, 3, 5, 7
    let odd_ctrl = m256i::from(ODD_TO_LANES);
    let r_odd = shuffle_av_i32_all_m256i(r_odd_raw, odd_ctrl);
    // r_odd = [0, r1, 0, r3, 0, r5, 0, r7]

    // Combine via bitwise OR
    bitor_m256i(r_even, r_odd)
    // = [r0, r1, r2, r3, r4, r5, r6, r7]
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
    // Extract low 32 bits of each i64 → positions [0, 2, 4, 6] go to [0, 1, 2, 3]
    let extract_lo = m256i::from([0i32, 2, 4, 6, 0, 0, 0, 0]);
    let a_lo = shuffle_av_i32_all_m256i(a, extract_lo);

    // Extract high 32 bits → positions [1, 3, 5, 7] go to [0, 1, 2, 3]
    let extract_hi = m256i::from([1i32, 3, 5, 7, 0, 0, 0, 0]);
    let a_hi = shuffle_av_i32_all_m256i(a, extract_hi);

    // t = a_lo * QINV (mod 2³²)
    let t = mul_i32_keep_low_m256i(a_lo, qinv);

    // t * Q  (via vpmuldq — t and Q must be at even positions)
    // Re-pack t[0..3] at positions 0, 2, 4, 6 (even)
    let repack_t = m256i::from([0i32, 0, 1, 0, 2, 0, 3, 0]);
    let t_even = shuffle_av_i32_all_m256i(t, repack_t);
    let tq = mul_i64_low_bits_m256i(t_even, q);

    // Extract low and high 32 bits of tq
    let tq_lo = shuffle_av_i32_all_m256i(tq, extract_lo);
    let tq_hi = shuffle_av_i32_all_m256i(tq, extract_hi);

    // Borrow: unsigned (a_lo < tq_lo)  →  XOR with 0x80000000 for unsigned cmp
    // cmp_gt_mask returns 0xFFFFFFFF (-1) when true, 0x00000000 when false.
    let borrow = cmp_gt_mask_i32_m256i(tq_lo ^ flip, a_lo ^ flip);
    // borrow is 0xFFFFFFFF (-1) where a_lo < tq_lo, 0 where a_lo >= tq_lo

    // result = a_hi - tq_hi + borrow
    // Because borrow = -1 when we need to subtract 1:
    //   a_hi - tq_hi + (-1) = a_hi - tq_hi - 1  ✓
    // And borrow = 0 when we don't:
    //   a_hi - tq_hi + 0 = a_hi - tq_hi  ✓
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
            // AVX2: process 4 pairs at a time (8 coefficients from each side)
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

            // Scalar tail
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

                // Inverse butterfly:
                //   sum = v0 + v1  (updated v0)
                //   diff = v0 - v1  → multiply by -ZETAS[k] via Montgomery
                let sum = add_i32_m256i(v0, v1);
                let diff = sub_i32_m256i(v0, v1);

                let t = montgomery_mul_vector(diff, zeta_neg);

                store_8_i32(sum, &mut coeffs[j..]);
                store_8_i32(t, &mut coeffs[j + len..]);
                j += 8;
            }

            // Scalar tail
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

    // Final scaling by F
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

        // Even elements
        let prod_even = mul_i64_low_bits_m256i(va, vb);
        let r_even_raw = montgomery_reduce_4x64(prod_even, q_v, qinv_v, flip);
        let even_ctrl = m256i::from(EVEN_TO_LANES);
        let r_even = shuffle_av_i32_all_m256i(r_even_raw, even_ctrl);

        // Odd elements (shuffle so odd positions align)
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
