//! AVX2 (256-bit SIMD) NTT backend for ML-KEM.
//!
//! Uses safe_arch for a safe-Rust AVX2 implementation.
//! Only compiled when the target has AVX2 (via `cfg(target_feature = "avx2")`).
//!
//! Montgomery reduction is implemented in pure i16 SIMD by splitting the i32
//! product into high/low 16-bit halves and detecting borrow via unsigned
//! comparison (sign-bit XOR + `cmp_gt_mask_i16_m256i`).

use safe_arch::*;

use crate::field::{barrett_reduce, montgomery_reduce};
use crate::ntt::ZETAS;
use crate::params::N;

#[inline(always)]
fn splat_i16(v: i16) -> m256i {
    set_splat_i16_m256i(v)
}

/// `montgomery_reduce(zeta * r)` across 16 i16 lanes.
#[inline(always)]
fn montgomery_mul_avx2(r: m256i, zeta: i16) -> m256i {
    let zeta_vec = splat_i16(zeta);
    let q = splat_i16(3329);
    let qinv = splat_i16(-3327);
    let flip = splat_i16(i16::MIN);

    // Full i32 product: a = zeta * r = (prod_high << 16) + (prod_low as u16)
    let prod_high = mul_i16_keep_high_m256i(r, zeta_vec);
    let prod_low = mul_i16_keep_low_m256i(r, zeta_vec);

    // t = (prod_low * QINV) mod 2^16
    let t = mul_i16_keep_low_m256i(prod_low, qinv);

    // t * Q (as i32, split into i16 halves)
    let tq_low = mul_i16_keep_low_m256i(t, q);
    let tq_high = mul_i16_keep_high_m256i(t, q);

    // Borrow detection: unsigned prod_low < tq_low ?
    // Flip sign bit (XOR 0x8000) to convert unsigned comparison to signed.
    let borrow = cmp_gt_mask_i16_m256i(tq_low ^ flip, prod_low ^ flip);
    // borrow is 0xFFFF where borrow=1, 0x0000 where borrow=0.
    // Subtracting 0xFFFF wraps to +1 in i16 arithmetic.

    // High half: prod_high - tq_high - borrow
    // Result = (a - t*Q) >> 16
    sub_i16_m256i(sub_i16_m256i(prod_high, tq_high), borrow)
}

#[inline(always)]
fn load_m256i(slice: &[i16]) -> m256i {
    m256i::from(<[i16; 16]>::try_from(&slice[..16]).expect("load_m256i: slice len >= 16"))
}

#[inline(always)]
fn store_m256i(v: m256i, slice: &mut [i16]) {
    slice[..16].copy_from_slice(&<[i16; 16]>::from(v));
}

pub(crate) fn ntt(r: &mut [i16; N]) {
    let mut k = 1usize;
    let mut len = 128;

    // AVX2 layers: len = 128, 64, 32, 16
    while len >= 16 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;

            let mut j = start;
            while j + 16 <= start + len {
                let v0 = load_m256i(&r[j..]);
                let v1 = load_m256i(&r[j + len..]);

                // t = montgomery(zeta * v1)
                let t = montgomery_mul_avx2(v1, zeta);
                // butterfly: v0' = v0 + t, v1' = v0 - t
                let new_v0 = add_i16_m256i(v0, t);
                let new_v1 = sub_i16_m256i(v0, t);

                store_m256i(new_v0, &mut r[j..]);
                store_m256i(new_v1, &mut r[j + len..]);
                j += 16;
            }

            // Tail (len < 16 after final AVX2 layer — won't trigger here)
            while j < start + len {
                let t = montgomery_reduce(i32::from(zeta) * i32::from(r[j + len]));
                r[j + len] = r[j].wrapping_sub(t);
                r[j] = r[j].wrapping_add(t);
                j += 1;
            }
            start = j + len; // = start + 2*len
        }
        len >>= 1;
    }

    // Scalar tail layers (len = 8, 4, 2)
    if len > 0 {
        soft_ntt_layers(r, len, k);
    }

    // Final Barrett reduction
    for coeff in r.iter_mut() {
        *coeff = barrett_reduce(*coeff);
    }
}

pub(crate) fn invntt(r: &mut [i16; N]) {
    let mut k = 127usize;
    let mut len = 2;

    // Scalar layers first (len = 2, 4, 8)
    while len < 16 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);
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

    // AVX2 layers: len = 16, 32, 64, 128
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);

            let mut j = start;
            while j + 16 <= start + len {
                let v0 = load_m256i(&r[j..]);
                let v1 = load_m256i(&r[j + len..]);

                // Inverse butterfly:
                //   sum  = v0 + v1       (needs Barrett reduction)
                //   new_v1 = v1 - v0     (multiply by zeta in Montgomery)
                let sum = add_i16_m256i(v0, v1);
                let new_v1 = montgomery_mul_avx2(sub_i16_m256i(v1, v0), zeta);

                // Barrett-reduce sum element-by-element (scalar — correct & simple)
                let mut sum_arr: [i16; 16] = sum.into();
                for s in &mut sum_arr {
                    *s = barrett_reduce(*s);
                }
                let new_v0 = m256i::from(sum_arr);

                store_m256i(new_v0, &mut r[j..]);
                store_m256i(new_v1, &mut r[j + len..]);
                j += 16;
            }

            // Tail elements
            while j < start + len {
                let t = r[j];
                r[j] = barrett_reduce({
                    i16::try_from(i32::from(t).wrapping_add(i32::from(r[j + len])))
                        .expect("sum of i16 values fits in i16")
                });
                r[j + len] = r[j + len].wrapping_sub(t);
                r[j + len] = montgomery_reduce(i32::from(zeta) * i32::from(r[j + len]));
                j += 1;
            }

            start += 2 * len;
        }
        len <<= 1;
    }

    // Multiply by scale factor n_inv = 1441
    scale_invntt_avx2(r);
}

fn scale_invntt_avx2(r: &mut [i16; N]) {
    const N_INV_I16: i16 = 1441;
    let mut j = 0;
    while j + 16 <= N {
        let v = load_m256i(&r[j..]);
        let v = montgomery_mul_avx2(v, N_INV_I16);
        store_m256i(v, &mut r[j..]);
        j += 16;
    }
    while j < N {
        r[j] = montgomery_reduce(i32::from(r[j]) * 1441);
        j += 1;
    }
}

pub(crate) fn poly_basemul(r: &mut [i16; N], a: &[i16; N], b: &[i16; N]) {
    // Basemul doesn't benefit from AVX2 without proper i16 shuffles — the
    // per-group zetas require lane-specific multipliers that safe_arch can't
    // express efficiently.  Use scalar for all groups.
    for i in 0..N / 4 {
        let zeta = i32::from(ZETAS[64 + i]);
        let neg_zeta = i32::from(-ZETAS[64 + i]);

        let a0 = i32::from(a[4 * i]);
        let a1 = i32::from(a[4 * i + 1]);
        let b0 = i32::from(b[4 * i]);
        let b1 = i32::from(b[4 * i + 1]);
        let (a2, a3) = (i32::from(a[4 * i + 2]), i32::from(a[4 * i + 3]));
        let (b2, b3) = (i32::from(b[4 * i + 2]), i32::from(b[4 * i + 3]));

        let t = montgomery_reduce(a1 * b1);
        let t = montgomery_reduce(i32::from(t) * zeta);
        r[4 * i] = t.wrapping_add(montgomery_reduce(a0 * b0));

        let t = montgomery_reduce(a0 * b1);
        r[4 * i + 1] = t.wrapping_add(montgomery_reduce(a1 * b0));

        let t = montgomery_reduce(a3 * b3);
        let t = montgomery_reduce(i32::from(t) * neg_zeta);
        r[4 * i + 2] = t.wrapping_add(montgomery_reduce(a2 * b2));

        let t = montgomery_reduce(a2 * b3);
        r[4 * i + 3] = t.wrapping_add(montgomery_reduce(a3 * b2));
    }
}

fn soft_ntt_layers(r: &mut [i16; N], mut len: usize, mut k: usize) {
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = montgomery_reduce(i32::from(zeta) * i32::from(r[j + len]));
                r[j + len] = r[j].wrapping_sub(t);
                r[j] = r[j].wrapping_add(t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}
