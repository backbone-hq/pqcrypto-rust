/// Returns 0xFFFF if `a == 0`; 0 otherwise (constant-time mask).
#[inline]
pub(crate) fn gf_iszero(a: u16) -> u16 {
    let t = u32::from(a).wrapping_sub(1);
    (t >> 19) as u16
}

/// Field addition = XOR.
#[inline]
pub(crate) fn gf_add(a: u16, b: u16) -> u16 {
    a ^ b
}

/// Field multiplication (GFBITS must be 12 or 13; the branch is monomorphized away).
#[inline]
pub(crate) fn gf_mul<const GFBITS: usize>(a: u16, b: u16) -> u16 {
    match GFBITS {
        12 => gf_mul_12(a, b),
        13 => gf_mul_13(a, b),
        _ => {
            // SAFETY: GFBITS is monomorphized to 12 or 13 by the variant parameter.
            unreachable!()
        }
    }
}

/// GF(2^12) multiplication — uses PCLMULQDQ when compiled with the `simd` feature
/// and the `pclmulqdq` target feature (e.g. via `-C target-cpu=native`);
/// otherwise uses a scalar bit-loop.
#[cfg(all(feature = "simd", target_feature = "pclmulqdq"))]
#[inline(always)]
fn gf_mul_12(a: u16, b: u16) -> u16 {
    use safe_arch::{m128i, mul_i64_carryless_m128i};
    let p = m128i::from([i64::from(a), 0i64]);
    let q = m128i::from([i64::from(b), 0i64]);
    let r: m128i = mul_i64_carryless_m128i::<0>(p, q);
    let res: [i64; 2] = r.into();
    let mut tmp = u32::try_from(res[0]).expect("PCLMULQDQ result fits in 32 bits");
    let mut t = tmp & 0x7FC000;
    tmp ^= t >> 9;
    tmp ^= t >> 12;
    t = tmp & 0x3000;
    tmp ^= t >> 9;
    tmp ^= t >> 12;
    (tmp & 0xFFF) as u16
}

/// GF(2^12) multiplication — scalar bit-loop fallback.
#[cfg(not(all(feature = "simd", target_feature = "pclmulqdq")))]
fn gf_mul_12(a: u16, b: u16) -> u16 {
    let t0 = u32::from(a);
    let t1 = u32::from(b);

    let mut tmp = t0 * (t1 & 1);
    for i in 1..12 {
        tmp ^= t0 * (t1 & (1 << i));
    }

    let mut t = tmp & 0x7FC000;
    tmp ^= t >> 9;
    tmp ^= t >> 12;

    t = tmp & 0x3000;
    tmp ^= t >> 9;
    tmp ^= t >> 12;

    (tmp & 0xFFF) as u16
}

/// GF(2^13) multiplication — uses PCLMULQDQ when compiled with the `simd` feature
/// and the `pclmulqdq` target feature; otherwise uses a scalar bit-loop.
#[cfg(all(feature = "simd", target_feature = "pclmulqdq"))]
#[inline(always)]
fn gf_mul_13(a: u16, b: u16) -> u16 {
    use safe_arch::{m128i, mul_i64_carryless_m128i};
    let p = m128i::from([i64::from(a), 0i64]);
    let q = m128i::from([i64::from(b), 0i64]);
    let r: m128i = mul_i64_carryless_m128i::<0>(p, q);
    let res: [i64; 2] = r.into();
    let mut tmp = u64::try_from(res[0]).expect("PCLMULQDQ result fits in 64 bits");
    let mut t = tmp & 0x1FF0000;
    tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    t = tmp & 0x000E000;
    tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    (tmp & 0x1FFF) as u16
}

/// GF(2^13) multiplication — scalar bit-loop fallback.
#[cfg(not(all(feature = "simd", target_feature = "pclmulqdq")))]
fn gf_mul_13(a: u16, b: u16) -> u16 {
    let t0 = u64::from(a);
    let t1 = u64::from(b);

    let mut tmp = t0 * (t1 & 1);
    for i in 1..13 {
        tmp ^= t0 * (t1 & (1 << i));
    }

    let mut t = tmp & 0x1FF0000;
    tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    t = tmp & 0x000E000;
    tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    (tmp & 0x1FFF) as u16
}

fn gf_sq_12(a: u16) -> u16 {
    const B: [u32; 4] = [0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF];
    let mut x = u32::from(a);
    x = (x | (x << 8)) & B[3];
    x = (x | (x << 4)) & B[2];
    x = (x | (x << 2)) & B[1];
    x = (x | (x << 1)) & B[0];
    let mut t = x & 0x7FC000;
    x ^= t >> 9;
    x ^= t >> 12;
    t = x & 0x3000;
    x ^= t >> 9;
    x ^= t >> 12;
    (x & 0xFFF) as u16
}

/// 4th power, not squaring!  Bit-interleaving `B[0]` has stride 4 (0x1111…)
/// rather than stride 2 (0x5555…), so this computes `a⁴`.
/// `gf_inv` is designed around this fact; never use as `a²` replacement.
fn gf_sq_13(a: u16) -> u16 {
    const B: [u64; 4] = [
        0x1111111111111111,
        0x0303030303030303,
        0x000F000F000F000F,
        0x000000FF000000FF,
    ];
    const M: [u64; 4] = [
        0x0001FF0000000000,
        0x000000FF80000000,
        0x000000007FC00000,
        0x00000000003FE000,
    ];
    let mut x = u64::from(a);
    x = (x | (x << 24)) & B[3];
    x = (x | (x << 12)) & B[2];
    x = (x | (x << 6)) & B[1];
    x = (x | (x << 3)) & B[0];
    for i in 0..4 {
        let t = x & M[i];
        x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    }
    (x & 0x1FFF) as u16
}

/// Field squaring: a² = a·a.
///
/// For GFBITS=12 this uses dedicated bit-interleaving (~6× faster than gf_mul).
/// For GFBITS=13 it falls back to gf_mul(a, a) because gf_sq_13 computes a⁴.
#[inline]
pub(crate) fn gf_sq<const GFBITS: usize>(a: u16) -> u16 {
    match GFBITS {
        12 => gf_sq_12(a),
        _ => gf_mul::<GFBITS>(a, a),
    }
}

/// Field inverse: a^(-1) = a^(2^GFBITS - 2) using explicit Itoh-Tsuji chain.
#[inline]
pub(crate) fn gf_inv<const GFBITS: usize>(a: u16) -> u16 {
    if a == 0 {
        return 0;
    }
    match GFBITS {
        12 => {
            let out = gf_sq_12(a);
            let tmp_11 = gf_mul_12(out, a);
            let out = gf_sq_12(tmp_11);
            let out = gf_sq_12(out);
            let tmp_1111 = gf_mul_12(out, tmp_11);
            let out = gf_sq_12(tmp_1111);
            let out = gf_sq_12(out);
            let out = gf_sq_12(out);
            let out = gf_sq_12(out);
            let out = gf_mul_12(out, tmp_1111);
            let out = gf_sq_12(out);
            let out = gf_sq_12(out);
            let out = gf_mul_12(out, tmp_11);
            let out = gf_sq_12(out);
            let out = gf_mul_12(out, a);
            gf_sq_12(out)
        }
        13 => {
            let out = gf_sq_13(a);
            let tmp_11 = gf_mul_13(out, a);
            let out = gf_sq_13(tmp_11);
            let out = gf_sq_13(out);
            let tmp_1111 = gf_mul_13(out, tmp_11);
            let out = gf_sq_13(tmp_1111);
            let out = gf_sq_13(out);
            let out = gf_sq_13(out);
            let out = gf_sq_13(out);
            let out = gf_mul_13(out, tmp_1111);
            let out = gf_sq_13(out);
            let out = gf_sq_13(out);
            let out = gf_mul_13(out, tmp_11);
            let out = gf_sq_13(out);
            let out = gf_mul_13(out, a);
            let out = gf_sq_13(out);
            let out = gf_mul_13(out, a);
            gf_sq_13(out)
        }
        _ => {
            // SAFETY: GFBITS is monomorphized to 12 or 13 by the variant parameter.
            unreachable!()
        }
    }
}

#[inline]
pub(crate) fn gf_frac<const GFBITS: usize>(den: u16, num: u16) -> u16 {
    gf_mul::<GFBITS>(gf_inv::<GFBITS>(den), num)
}
