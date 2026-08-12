#![allow(clippy::cast_possible_truncation)]
// All casts in this module operate on bounded values (byte/limb extraction, loop counters).
//! SNTRUP KEM: key generation, encapsulation, decapsulation.
//!
//! Generic over ring dimension `P` and modulus `Q`.
//! Variant-specific constants (weight `w`, ciphertext size `ct_bytes`) are
//! passed at call time.

use crate::poly::{r3_encoded_bytes, rq_encoded_bytes, rq_rounded_bytes, Rq, R3};
use alloc::vec;
use alloc::vec::Vec;
use backbone_pqcrypto_internals::nist_seed_expander::NistSeedExpander;
use backbone_pqcrypto_internals::secret::{SecretArray, SecretVec};
use sha2::{Digest, Sha512};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use subtle::{ConditionallySelectable, ConstantTimeEq};

pub(crate) fn prng(seed: &[u8], out: &mut [u8]) {
    let mut shake = Shake256::default();
    shake.update(seed);
    let mut reader = shake.finalize_xof();
    reader.read(out);
}

fn hash_prefix(prefix: u8, input: &[u8]) -> [u8; 32] {
    let mut h = Sha512::new();
    Digest::update(&mut h, [prefix]);
    Digest::update(&mut h, input);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn hash_confirm(inputs: &[u8], cache: &[u8; 32]) -> [u8; 32] {
    let h3 = hash_prefix(3, inputs);
    let mut x = SecretVec::<u8>::new(64);
    x[..32].copy_from_slice(&h3);
    x[32..].copy_from_slice(cache);
    hash_prefix(2, &x)
}

fn hash_session(prefix: u8, inputs: &[u8], ct: &[u8]) -> [u8; 32] {
    let h3 = hash_prefix(3, inputs);
    let len = 32 + ct.len();
    let mut x = SecretVec::<u8>::new(len);
    x[..32].copy_from_slice(&h3);
    x[32..len].copy_from_slice(ct);
    hash_prefix(prefix, &x)
}

fn uint32_minmax_pair(a: u32, b: u32) -> (u32, u32) {
    let xy = a ^ b;
    let mut c = b.wrapping_sub(a);
    c ^= xy & (c ^ b ^ 0x8000_0000);
    c >>= 31;
    c = c.wrapping_neg();
    c &= xy;
    (a ^ c, b ^ c)
}

fn uint32_sort(values: &mut [u32]) {
    let n = values.len();
    if n < 2 {
        return;
    }

    let mut top = 1usize;
    while top < n - top {
        top += top;
    }

    let mut p = top;
    while p > 0 {
        for i in 0..(n - p) {
            if (i & p) == 0 {
                let (a, b) = uint32_minmax_pair(values[i], values[i + p]);
                values[i] = a;
                values[i + p] = b;
            }
        }

        let mut q = top;
        while q > p {
            for i in 0..(n - q) {
                if (i & p) == 0 {
                    let (a, b) = uint32_minmax_pair(values[i + p], values[i + q]);
                    values[i + p] = a;
                    values[i + q] = b;
                }
            }
            q >>= 1;
        }

        p >>= 1;
    }
}

fn mod3_freeze_i8(a: i32) -> i8 {
    let mut a = a;
    a -= 3 * ((10923 * a) >> 15);
    a -= 3 * ((89478485 * a + 134217728) >> 28);
    i8::try_from(a).expect("mod3_freeze_i8: value reduced to {-1,0,1}")
}

fn mod3_product(a: i8, b: i8) -> i8 {
    a * b
}

fn mod3_minusproduct(a: i8, b: i8, c: i8) -> i8 {
    mod3_freeze_i8(i32::from(a) - i32::from(b) * i32::from(c))
}

fn mod3_nonzero_mask(x: i8) -> i32 {
    -i32::from(x) * i32::from(x)
}

fn mod3_reciprocal(a: i8) -> i8 {
    a
}

fn mod3_quotient(num: i8, den: i8) -> i8 {
    mod3_product(num, mod3_reciprocal(den))
}

pub(crate) fn r3_recip<const P: usize>(s: &R3<P>) -> Result<R3<P>, ()> {
    let loops = 2 * P + 1;

    let mut f = SecretVec::<i8>::new(P + 1);
    f[0] = -1;
    f[1] = -1;
    f[P] = 1;

    let mut g = SecretVec::<i8>::new(P + 1);
    for i in 0..P {
        g[i] = s.0[i];
    }

    let mut u = SecretVec::<i8>::new(loops + 1);
    let mut v = SecretVec::<i8>::new(loops + 1);
    v[0] = 1;

    let mut d = i32::try_from(P).expect("P fits in i32");
    let mut e = i32::try_from(P).expect("P fits in i32");

    for loop_idx in 0..loops {
        let c = mod3_quotient(g[P], f[P]);

        for i in 0..=P {
            g[i] = mod3_minusproduct(g[i], f[i], c);
        }
        g.copy_within(0..P, 1);
        g[0] = 0;

        if i32::try_from(loop_idx).expect("loop_idx fits in i32")
            < i32::try_from(P).expect("P fits in i32")
        {
            for i in 0..=loop_idx {
                v[i] = mod3_minusproduct(v[i], u[i], c);
            }
            v.copy_within(0..=loop_idx, 1);
            v[0] = 0;
        } else {
            for i in 0..=P {
                v[loop_idx - P + i] =
                    mod3_minusproduct(v[loop_idx - P + i], u[loop_idx - P + i], c);
            }
            let start = loop_idx - P;
            v.copy_within(start..start + P + 1, start + 1);
            v[start] = 0;
        }

        e -= 1;

        let smaller_mask = (e - d) >> 31;
        let swapmask = smaller_mask & mod3_nonzero_mask(g[P]);

        let mask8 = swapmask as i8;
        {
            let delta = (e ^ d) & swapmask;
            e ^= delta;
            d ^= delta;
        }
        for i in 0..=P {
            let delta = (f[i] ^ g[i]) & mask8;
            f[i] ^= delta;
            g[i] ^= delta;
        }
        if loop_idx + 1 < P {
            for i in 0..=loop_idx + 1 {
                let delta = (u[i] ^ v[i]) & mask8;
                u[i] ^= delta;
                v[i] ^= delta;
            }
        } else {
            for i in 0..=P {
                let idx = loop_idx + 1 - P + i;
                let delta = (u[idx] ^ v[idx]) & mask8;
                u[idx] ^= delta;
                v[idx] ^= delta;
            }
        }
    }

    let c = mod3_reciprocal(f[P]);
    let mut result = R3::<P>::default();
    for i in 0..P {
        result.0[i] = mod3_product(u[P + i], c);
    }

    let prod = s.mul(&result);
    let mut ok = true;
    ok &= prod.0[0] == 1;
    for i in 1..P {
        ok &= prod.0[i] == 0;
    }

    if ok {
        Ok(result)
    } else {
        Err(())
    }
}

/// Rq reciprocal: compute 1/(3*f) in Rq = (Z/qZ)[x]/(x^p - x - 1).
///
/// Dispatch: the AVX2 backend (div-free vector Barrett inner updates) is
/// used when compiled with `features = ["simd"]` and `target_feature =
/// "avx2"`; otherwise the portable scalar implementation is used.
fn rq_recip3<const P: usize, const Q: i16>(f3: &Rq<P, Q>) -> Result<Rq<P, Q>, ()> {
    #[cfg(all(feature = "simd", target_feature = "avx2"))]
    return rq_recip3_avx2(f3);
    #[cfg(not(all(feature = "simd", target_feature = "avx2")))]
    rq_recip3_soft(f3)
}

/// Scalar Rq reciprocal — the reference implementation. Each inner update
/// uses `modq_mul`/`modq_sub`, which reduce via hardware division
/// (`% q`); results are byte-for-byte identical to `rq_recip3_avx2`.
/// Kept compiled under `cfg(test)` in simd builds for the differential
/// test; in non-simd builds it is the production implementation.
#[cfg(any(not(all(feature = "simd", target_feature = "avx2")), test))]
fn rq_recip3_soft<const P: usize, const Q: i16>(f3: &Rq<P, Q>) -> Result<Rq<P, Q>, ()> {
    let loops = 2 * P + 1;

    let mut f = SecretVec::<i32>::new(P + 1);
    f[0] = -1;
    f[1] = -1;
    f[P] = 1;

    let mut g = SecretVec::<i32>::new(P + 1);
    for i in 0..P {
        g[i] = 3 * i32::from(f3.0[i]);
    }
    g[P] = 0;

    let mut u = SecretVec::<i32>::new(loops + 1);
    let mut v = SecretVec::<i32>::new(loops + 1);
    v[0] = 1;

    let mut d = i32::try_from(P).expect("P fits in i32");
    let mut e = i32::try_from(P).expect("P fits in i32");

    for loop_idx in 0..loops {
        let c = modq_divide::<Q>(g[P], f[P]);

        for i in 0..=P {
            g[i] = modq_sub::<Q>(g[i], modq_mul::<Q>(c, f[i]));
        }
        g.copy_within(0..P, 1);
        g[0] = 0;

        if i32::try_from(loop_idx).expect("loop_idx fits in i32")
            < i32::try_from(P).expect("P fits in i32")
        {
            for i in 0..=loop_idx {
                v[i] = modq_sub::<Q>(v[i], modq_mul::<Q>(c, u[i]));
            }
            v.copy_within(0..=loop_idx, 1);
            v[0] = 0;
        } else {
            for i in 0..=P {
                v[loop_idx - P + i] =
                    modq_sub::<Q>(v[loop_idx - P + i], modq_mul::<Q>(c, u[loop_idx - P + i]));
            }
            let start = loop_idx - P;
            v.copy_within(start..start + P + 1, start + 1);
            v[start] = 0;
        }

        e -= 1;

        let smaller_mask = (e - d) >> 31;
        let swapmask = smaller_mask & modq_nonzero_mask::<Q>(g[P]);

        {
            let delta = (e ^ d) & swapmask;
            e ^= delta;
            d ^= delta;
        }
        for i in 0..=P {
            let delta = (f[i] ^ g[i]) & swapmask;
            f[i] ^= delta;
            g[i] ^= delta;
        }
        if loop_idx + 1 < P {
            for i in 0..=loop_idx + 1 {
                let delta = (u[i] ^ v[i]) & swapmask;
                u[i] ^= delta;
                v[i] ^= delta;
            }
        } else {
            for i in 0..=P {
                let idx = loop_idx + 1 - P + i;
                let delta = (u[idx] ^ v[idx]) & swapmask;
                u[idx] ^= delta;
                v[idx] ^= delta;
            }
        }
    }

    if f[P] == 0 {
        return Err(());
    }
    let c = modq_reciprocal::<Q>(f[P]);
    let mut r = Rq::<P, Q>::default();
    for i in 0..P {
        r.0[i] = i16::try_from(modq_mul::<Q>(u[P + i], c)).expect("modq_mul result fits in i16");
    }

    Ok(r)
}

/// Exact div-free reduction of `x` mod `Q` for `x` in `[0, 2^32)` via
/// Barrett: `mu = ceil(2^32 / Q)`, `t = floor(x*mu / 2^32)` is within 1 of
/// `floor(x/Q)` for all `Q < 2^16` and `x < 2^32`, so one branchless
/// conditional add of `Q` lands the result in `[0, Q)`.
#[cfg(all(feature = "simd", target_feature = "avx2"))]
fn barrett_mu<const Q: i16>() -> i64 {
    (((1u64 << 32).wrapping_add(Q as u64 - 1)) / Q as u64) as i64
}

/// `out[i] = (out[i] - c*src[i]) mod Q` for `i in 0..n`, all values in
/// `[0, Q)`. Vectorized 4 lanes at a time: `vpmuludq` computes the
/// 64-bit products, Barrett via `(p*mu) >> 32` replaces the scalar
/// hardware division, and the conditional fixups are branchless masks.
/// No secret-dependent branches, no secret-indexed memory, no `unsafe`.
#[cfg(all(feature = "simd", target_feature = "avx2"))]
fn update_sub_mul<const Q: i16>(out: &mut [i32], src: &[i32], c: i32, n: usize) {
    use safe_arch::*;
    let q = i64::from(Q);
    let mu = barrett_mu::<Q>();
    let vc = set_splat_i64_m256i(c as i64);
    let vmu = set_splat_i64_m256i(mu);
    let vq = set_splat_i64_m256i(q);
    let vzero = set_splat_i64_m256i(0);
    let mut i = 0;
    while i + 4 <= n {
        let vg = m256i::from([
            out[i] as i64,
            out[i + 1] as i64,
            out[i + 2] as i64,
            out[i + 3] as i64,
        ]);
        let vf = m256i::from([
            src[i] as i64,
            src[i + 1] as i64,
            src[i + 2] as i64,
            src[i + 3] as i64,
        ]);
        let p = mul_u64_low_bits_m256i(vf, vc); // c*src[i] < Q^2 < 2^26
        let tp = mul_u64_low_bits_m256i(p, vmu); // p*mu < 2^46
        let t = shr_imm_u64_m256i::<32>(tp); // floor(p*mu / 2^32)
        let tq = mul_u64_low_bits_m256i(t, vq); // t*Q
        let r0 = sub_i64_m256i(p, tq); // in [-Q, Q)
        let neg = cmp_gt_mask_i64_m256i(vzero, r0); // all-ones iff r0 < 0
        let r = add_i64_m256i(r0, bitand_m256i(neg, vq)); // in [0, Q)
        let o0 = sub_i64_m256i(vg, r); // in (-Q, Q)
        let neg2 = cmp_gt_mask_i64_m256i(vzero, o0);
        let o = add_i64_m256i(o0, bitand_m256i(neg2, vq));
        let res: [i64; 4] = o.into();
        out[i] = res[0] as i32;
        out[i + 1] = res[1] as i32;
        out[i + 2] = res[2] as i32;
        out[i + 3] = res[3] as i32;
        i += 4;
    }
    // Branchless scalar tail (arithmetic shift >> 63 = -1 iff negative).
    for j in i..n {
        let p = (c as i64) * (src[j] as i64);
        let t = (p * mu) >> 32;
        let r0 = p - t * q;
        let r = r0 + (q & (r0 >> 63));
        let o0 = (out[j] as i64) - r;
        let o = o0 + (q & (o0 >> 63));
        out[j] = o as i32;
    }
}

/// `(a[i], b[i]) = (b[i], a[i])` masked by `mask` (0 or -1) for
/// `i in 0..n`. Vectorized 4 lanes at a time; branchless.
#[cfg(all(feature = "simd", target_feature = "avx2"))]
fn swap_masked(a: &mut [i32], b: &mut [i32], mask: i32, n: usize) {
    use safe_arch::*;
    let vm = set_splat_i64_m256i(mask as i64);
    let mut i = 0;
    while i + 4 <= n {
        let va = m256i::from([
            a[i] as i64,
            a[i + 1] as i64,
            a[i + 2] as i64,
            a[i + 3] as i64,
        ]);
        let vb = m256i::from([
            b[i] as i64,
            b[i + 1] as i64,
            b[i + 2] as i64,
            b[i + 3] as i64,
        ]);
        let delta = bitand_m256i(bitxor_m256i(va, vb), vm);
        let na = bitxor_m256i(va, delta);
        let nb = bitxor_m256i(vb, delta);
        let ra: [i64; 4] = na.into();
        let rb: [i64; 4] = nb.into();
        a[i] = ra[0] as i32;
        a[i + 1] = ra[1] as i32;
        a[i + 2] = ra[2] as i32;
        a[i + 3] = ra[3] as i32;
        b[i] = rb[0] as i32;
        b[i + 1] = rb[1] as i32;
        b[i + 2] = rb[2] as i32;
        b[i + 3] = rb[3] as i32;
        i += 4;
    }
    for j in i..n {
        let delta = (a[j] ^ b[j]) & mask;
        a[j] ^= delta;
        b[j] ^= delta;
    }
}

/// AVX2 Rq reciprocal — same extended-Euclid algorithm as `rq_recip3_soft`,
/// with the four hot inner loops (g/v updates and the masked f/g, u/v
/// swaps) replaced by div-free vector Barrett arithmetic via `safe_arch`.
/// Byte-for-byte identical to `rq_recip3_soft` (proven by differential
/// tests and the full KAT suite).
#[cfg(all(feature = "simd", target_feature = "avx2"))]
fn rq_recip3_avx2<const P: usize, const Q: i16>(f3: &Rq<P, Q>) -> Result<Rq<P, Q>, ()> {
    let loops = 2 * P + 1;

    let mut f = SecretVec::<i32>::new(P + 1);
    f[0] = -1;
    f[1] = -1;
    f[P] = 1;

    let mut g = SecretVec::<i32>::new(P + 1);
    for i in 0..P {
        g[i] = 3 * i32::from(f3.0[i]);
    }
    g[P] = 0;

    let mut u = SecretVec::<i32>::new(loops + 1);
    let mut v = SecretVec::<i32>::new(loops + 1);
    v[0] = 1;

    let mut d = i32::try_from(P).expect("P fits in i32");
    let mut e = i32::try_from(P).expect("P fits in i32");

    for loop_idx in 0..loops {
        // Single scalar division per iteration (modq_divide + reciprocal) —
        // a tiny fraction of the work; everything else is vectorized.
        let c = modq_divide::<Q>(g[P], f[P]);

        update_sub_mul::<Q>(&mut g, &f, c, P + 1);
        g.copy_within(0..P, 1);
        g[0] = 0;

        if i32::try_from(loop_idx).expect("loop_idx fits in i32")
            < i32::try_from(P).expect("P fits in i32")
        {
            update_sub_mul::<Q>(&mut v, &u, c, loop_idx + 1);
            v.copy_within(0..=loop_idx, 1);
            v[0] = 0;
        } else {
            let start = loop_idx - P;
            update_sub_mul::<Q>(&mut v[start..=start + P], &u[start..=start + P], c, P + 1);
            v.copy_within(start..start + P + 1, start + 1);
            v[start] = 0;
        }

        e -= 1;

        let smaller_mask = (e - d) >> 31;
        let swapmask = smaller_mask & modq_nonzero_mask::<Q>(g[P]);

        {
            let delta = (e ^ d) & swapmask;
            e ^= delta;
            d ^= delta;
        }
        swap_masked(&mut f, &mut g, swapmask, P + 1);
        if loop_idx + 1 < P {
            swap_masked(&mut u, &mut v, swapmask, loop_idx + 2);
        } else {
            let start = loop_idx + 1 - P;
            swap_masked(
                &mut u[start..=start + P],
                &mut v[start..=start + P],
                swapmask,
                P + 1,
            );
        }
    }

    if f[P] == 0 {
        return Err(());
    }
    let c = modq_reciprocal::<Q>(f[P]);
    let mut r = Rq::<P, Q>::default();
    for i in 0..P {
        r.0[i] = i16::try_from(modq_mul::<Q>(u[P + i], c)).expect("modq_mul result fits in i16");
    }

    Ok(r)
}

/// Used by the scalar inverse only; kept for the differential test in
/// simd builds (see `rq_recip3_soft`).
#[cfg(any(not(all(feature = "simd", target_feature = "avx2")), test))]
fn modq_sub<const Q: i16>(a: i32, b: i32) -> i32 {
    let q = i32::from(Q);
    let r = (a - b) % q;
    r + (q & (r >> 31))
}

fn modq_mul<const Q: i16>(a: i32, b: i32) -> i32 {
    let q = i32::from(Q);
    ((a % q) * (b % q)) % q
}

fn modq_nonzero_mask<const Q: i16>(x: i32) -> i32 {
    let q = i32::from(Q);
    let r = i16::try_from(x.rem_euclid(q)).expect("rem_euclid in [0,Q) fits i16");
    let r32 = -i32::from(u16::from_ne_bytes(r.to_ne_bytes()));
    r32 >> 30
}

fn modq_divide<const Q: i16>(a: i32, b: i32) -> i32 {
    let q = i32::from(Q);
    modq_mul::<Q>(a % q, modq_reciprocal::<Q>(b % q))
}

fn modq_reciprocal<const Q: i16>(a: i32) -> i32 {
    let q = i32::from(Q);
    let mut t = 0i32;
    let mut newt = 1i32;
    let mut r = q;
    let mut newr = a % q;
    newr += q & (newr >> 31);
    while newr != 0 {
        let quotient = r / newr;
        let tmp_t = t;
        t = newt;
        newt = tmp_t - quotient * newt;
        let tmp_r = r;
        r = newr;
        newr = tmp_r - quotient * newr;
    }
    if t < 0 {
        t + q
    } else {
        t
    }
}

fn words_from_bytes(bytes: &[u8]) -> SecretVec<u32> {
    let n = bytes.len() / 4;
    let mut out = SecretVec::<u32>::new(n);
    for (i, c) in bytes.chunks_exact(4).enumerate() {
        out[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    out
}

fn short_from_words<const P: usize>(words: &[u32], w: usize) -> R3<P> {
    let mut list = SecretVec::<u32>::new(P);
    for i in 0..w {
        list[i] = words[i] & !1;
    }
    for i in w..P {
        list[i] = (words[i] & !3) | 1;
    }
    uint32_sort(&mut list);
    let mut poly = R3::<P>::default();
    for i in 0..P {
        poly.0[i] = i8::try_from(list[i] & 3).expect("low bits fit in i8") - 1;
    }
    poly
}

pub(crate) fn random_weightw<const P: usize>(seed: &[u8], w: usize) -> R3<P> {
    let mut rnd = SecretVec::<u8>::new(4 * P);
    prng(seed, rnd.as_mut());
    short_from_words::<P>(&words_from_bytes(rnd.as_ref()), w)
}

fn random_small_from_words<const P: usize>(words: &[u32]) -> R3<P> {
    let mut poly = R3::<P>::default();
    for i in 0..P {
        let v = (((u64::from(words[i] & 0x3fff_ffff)) * 3) >> 30) as i8;
        poly.0[i] = v - 1;
    }
    poly
}

pub(crate) fn keypair_drbg<const P: usize, const Q: i16>(
    expander: &mut NistSeedExpander,
    pk: &mut [u8],
    sk: &mut [u8],
    w: usize,
) -> Result<(), crate::error::Error> {
    let pk_bytes = rq_encoded_bytes(P, Q);
    let r3_enc = r3_encoded_bytes(P);
    if pk.len() != pk_bytes {
        return Err(crate::error::Error::InvalidKeyLength);
    }
    if sk.len() != 2 * r3_enc + pk_bytes + r3_enc + 32 {
        return Err(crate::error::Error::InvalidSecretKeyLength);
    }

    let mut word_buf = SecretArray::<u8, 4>::new();
    let (g, grecip) = loop {
        let mut g_words = SecretVec::<u32>::new(P);
        for i in 0..P {
            expander.fill_bytes(word_buf.as_mut());
            g_words[i] = u32::from_le_bytes(*word_buf);
        }
        let g = random_small_from_words::<P>(g_words.as_ref());
        if let Ok(grecip) = r3_recip::<P>(&g) {
            break (g, grecip);
        }
    };

    let mut f_words = SecretVec::<u32>::new(P);
    for i in 0..P {
        expander.fill_bytes(word_buf.as_mut());
        f_words[i] = u32::from_le_bytes(*word_buf);
    }
    let f = short_from_words::<P>(f_words.as_ref(), w);

    let mut f_rq = Rq::<P, Q>::default();
    for i in 0..P {
        f_rq.0[i] = i16::from(f.0[i]);
    }
    let recip = rq_recip3::<P, Q>(&f_rq).map_err(|_| crate::error::Error::NotInvertible)?;
    let mut g_rq = Rq::<P, Q>::default();
    for i in 0..P {
        g_rq.0[i] = i16::from(g.0[i]);
    }
    let h = recip.mul(&g_rq);

    h.encode(pk)
        .map_err(|_| crate::error::Error::InvalidKeyLength)?;

    f.encode(&mut sk[..r3_enc])
        .expect("sk buffer is exactly r3_enc");
    grecip
        .encode(&mut sk[r3_enc..2 * r3_enc])
        .expect("sk buffer is exactly 2*r3_enc");
    let pk_start = 2 * r3_enc;
    sk[pk_start..pk_start + pk_bytes].copy_from_slice(pk);
    let rho_start = pk_start + pk_bytes;
    expander.fill_bytes(&mut sk[rho_start..rho_start + r3_enc]);
    let cache = hash_prefix(4, pk);
    sk[rho_start + r3_enc..rho_start + r3_enc + 32].copy_from_slice(&cache);

    Ok(())
}

pub(crate) fn encaps<const P: usize, const Q: i16>(
    pk: &[u8],
    r_seed: &[u8],
    w: usize,
    ct_bytes: usize,
) -> Result<([u8; 32], Vec<u8>), crate::error::Error> {
    let r = random_weightw::<P>(r_seed, w);
    encaps_core::<P, Q>(pk, &r, ct_bytes)
}

#[cfg(test)]
pub(crate) fn encaps_with_r_enc<const P: usize, const Q: i16>(
    pk: &[u8],
    r_enc: &[u8],
    ct_bytes: usize,
) -> Result<([u8; 32], Vec<u8>), crate::error::Error> {
    let r3_enc = r3_encoded_bytes(P);
    if r_enc.len() != r3_enc {
        return Err(crate::error::Error::InvalidKeyLength);
    }
    let r = R3::<P>::decode(r_enc).map_err(|_| crate::error::Error::InvalidKeyLength)?;
    encaps_core::<P, Q>(pk, &r, ct_bytes)
}

fn encaps_core<const P: usize, const Q: i16>(
    pk: &[u8],
    r: &R3<P>,
    ct_bytes: usize,
) -> Result<([u8; 32], Vec<u8>), crate::error::Error> {
    let pk_bytes = rq_encoded_bytes(P, Q);
    let r3_enc = r3_encoded_bytes(P);
    let rounded_bytes = rq_rounded_bytes(P, Q);

    if pk.len() != pk_bytes {
        return Err(crate::error::Error::InvalidKeyLength);
    }

    let h = Rq::<P, Q>::decode(pk).map_err(|_| crate::error::Error::InvalidKeyLength)?;

    let mut r_enc = SecretVec::<u8>::new(r3_enc);
    r.encode(&mut r_enc)
        .expect("r_enc buffer is exactly r3_enc");

    let hr = h.mul_small(r);
    let mut c = Rq::<P, Q>::default();
    for i in 0..P {
        c.0[i] = hr.0[i];
    }
    let rounded = c.round3();

    let mut ct = vec![0u8; ct_bytes];
    if ct_bytes != rounded_bytes + 32 {
        return Err(crate::error::Error::InvalidCiphertextLength);
    }
    rounded
        .encode_rounded(&mut ct[..rounded_bytes])
        .expect("ct buffer is exactly rounded_bytes");
    let cache = hash_prefix(4, pk);
    let confirm = hash_confirm(&r_enc, &cache);
    ct[rounded_bytes..].copy_from_slice(&confirm);

    let ss = hash_session(1, &r_enc, &ct);

    Ok((ss, ct))
}

pub(crate) fn decaps<const P: usize, const Q: i16>(
    sk: &[u8],
    ct: &[u8],
    w: usize,
) -> Result<[u8; 32], crate::error::Error> {
    let r3_enc = r3_encoded_bytes(P);
    let pk_bytes = rq_encoded_bytes(P, Q);
    let rounded_bytes = rq_rounded_bytes(P, Q);
    let expected_ct_len = rounded_bytes + 32;
    let expected_sk_len = 2 * r3_enc + pk_bytes + r3_enc + 32;

    if sk.len() != expected_sk_len {
        return Err(crate::error::Error::InvalidSecretKeyLength);
    }
    if ct.len() != expected_ct_len {
        return Err(crate::error::Error::InvalidCiphertextLength);
    }

    let f =
        R3::<P>::decode(&sk[..r3_enc]).map_err(|_| crate::error::Error::InvalidSecretKeyLength)?;
    let grecip = R3::<P>::decode(&sk[r3_enc..2 * r3_enc])
        .map_err(|_| crate::error::Error::InvalidSecretKeyLength)?;
    let pk_start = 2 * r3_enc;
    let pk = &sk[pk_start..pk_start + pk_bytes];
    let rho = &sk[pk_start + pk_bytes..pk_start + pk_bytes + r3_enc];
    let cache: &[u8; 32] = sk[pk_start + pk_bytes + r3_enc..pk_start + pk_bytes + r3_enc + 32]
        .try_into()
        .expect("cache length checked by sk length");

    let rounded_c = Rq::<P, Q>::decode_rounded(&ct[..rounded_bytes])
        .map_err(|_| crate::error::Error::InvalidCiphertextLength)?;

    let t = rounded_c.mul_small(&f);

    let q = i32::from(Q);
    let qs = crate::poly::qshift(Q);
    let mut t3 = R3::<P>::default();
    for i in 0..P {
        let mut val = (3i32 * i32::from(t.0[i])) % q;
        // Constant-time centering: the previous if/else branched on the
        // secret-derived `val` (t = rounded_c * f with f the secret key) and
        // leaked f-derived bits via timing. Mask arithmetic is branchless.
        val -= q * i32::from(val > qs);
        val += q * i32::from(val < -qs);
        t3.0[i] = mod3_freeze_i8(val);
    }

    let r_recovered = t3.mul(&grecip);

    let mut r_dec = r_recovered;
    let weight = r_dec.ct_weight();
    // CT: ct_ne returns Choice directly, no branching on secret weight value
    let replace = (weight as u32).ct_ne(&(w as u32));
    for i in 0..P {
        let fallback = if i < w { 1i8 } else { 0i8 };
        r_dec.0[i] = i8::conditional_select(&r_dec.0[i], &fallback, replace);
    }

    let mut r_enc = SecretVec::new(r3_enc);
    r_dec
        .encode(&mut r_enc[..])
        .expect("r_enc buffer is exactly r3_enc");

    let h = Rq::<P, Q>::decode(pk).map_err(|_| crate::error::Error::InvalidSecretKeyLength)?;
    let cnew = h.mul_small(&r_dec).round3();
    let mut expected_ct = vec![0u8; expected_ct_len];
    cnew.encode_rounded(&mut expected_ct[..rounded_bytes])
        .expect("expected_ct buffer is exactly rounded_bytes");
    let confirm = hash_confirm(&r_enc[..], cache);
    expected_ct[rounded_bytes..].copy_from_slice(&confirm);
    let fail = ct.ct_ne(&expected_ct[..]);
    for i in 0..r3_enc {
        r_enc[i].conditional_assign(&rho[i], fail);
    }
    Ok(hash_session(1 - fail.unwrap_u8(), &r_enc[..], ct))
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: usize = 761;
    const Q: i16 = 4591;
    const W: usize = 286;
    const CT_BYTES: usize = rq_rounded_bytes(P, Q) + 32;

    #[test]
    fn test_r3_recip_identity() {
        let one = R3::<P>::constant(1);
        let inv = r3_recip::<P>(&one).unwrap();
        assert_eq!(inv, one);
    }

    #[test]
    fn test_random_weightw_weight() {
        let seed = [0x12u8; 32];
        let f = random_weightw::<P>(&seed, W);
        assert_eq!(f.ct_weight(), W);
    }

    #[test]
    fn test_random_weightw_deterministic() {
        let seed = [0x12u8; 32];
        let f1 = random_weightw::<P>(&seed, W);
        let f2 = random_weightw::<P>(&seed, W);
        assert_eq!(f1, f2);
    }

    #[test]
    fn test_rq_recip3_simple() {
        let one = R3::<P>::constant(1);
        let mut f_rq = Rq::<P, Q>::default();
        for i in 0..P {
            f_rq.0[i] = i16::from(one.0[i]);
        }
        let recip = rq_recip3::<P, Q>(&f_rq).unwrap();
        let mut f3_rq = Rq::<P, Q>::default();
        for i in 0..P {
            f3_rq.0[i] = (3 * i32::from(one.0[i])) as i16;
        }
        let prod = f3_rq.mul(&recip);
        assert_eq!(prod.0[0], 1, "product constant term should be 1");
        for i in 1..P {
            assert_eq!(prod.0[i], 0, "product coeff [{}] should be 0", i);
        }
    }

    /// AVX2 inverse must be byte-for-byte identical to the scalar inverse
    /// — same coefficients, same Ok/Err — on random and degenerate inputs.
    #[cfg(all(feature = "simd", target_feature = "avx2"))]
    #[test]
    fn test_rq_recip3_avx2_matches_soft() {
        let mut rng =
            backbone_pqcrypto_internals::testutil::XorShift::from_seed(0x9E37_79B9_7F4A_7C15);
        for _ in 0..64 {
            let mut f_rq = Rq::<P, Q>::default();
            for v in f_rq.0.iter_mut() {
                *v = ((rng.next_u64() >> 33) % 4591) as i16;
            }
            let soft = rq_recip3_soft::<P, Q>(&f_rq);
            let avx2 = rq_recip3_avx2::<P, Q>(&f_rq);
            assert_eq!(
                soft.is_ok(),
                avx2.is_ok(),
                "Ok/Err divergence for f[0..3]={:?}",
                &f_rq.0[..3]
            );
            if let (Ok(s), Ok(a)) = (soft, avx2) {
                for i in 0..P {
                    assert_eq!(s.0[i], a.0[i], "recip mismatch at {i}");
                }
            }
        }
        // Degenerate input: all-zero f — the algorithm returns Ok(0) from
        // both implementations (real keygen never produces it since f has
        // weight w); assert they agree rather than assuming an error.
        let zero = Rq::<P, Q>::default();
        let s = rq_recip3_soft::<P, Q>(&zero).unwrap();
        let a = rq_recip3_avx2::<P, Q>(&zero).unwrap();
        for i in 0..P {
            assert_eq!(s.0[i], a.0[i], "zero-input recip mismatch at {i}");
        }
    }

    #[test]
    fn test_keygen_roundtrip() {
        let seed = [0x42u8; 48];
        let pk_bytes = rq_encoded_bytes(P, Q);
        let sk_bytes = 2 * r3_encoded_bytes(P) + pk_bytes + r3_encoded_bytes(P) + 32;
        let mut pk = vec![0u8; pk_bytes];
        let mut sk = vec![0u8; sk_bytes];
        let mut expander = NistSeedExpander::new(&seed);
        keypair_drbg::<P, Q>(&mut expander, &mut pk, &mut sk, W).unwrap();
        assert_eq!(pk.len(), pk_bytes);
        assert_eq!(sk.len(), sk_bytes);
        assert!(pk.iter().any(|&b| b != 0));
        assert!(sk.iter().any(|&b| b != 0));

        let r_seed = [0x13u8; 32];
        let (ss_enc, ct) = encaps::<P, Q>(&pk, &r_seed, W, CT_BYTES).unwrap();
        let ss_dec = decaps::<P, Q>(&sk, &ct, W).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_keygen_math() {
        let seed = [0x42u8; 48];
        let pk_bytes = rq_encoded_bytes(P, Q);
        let sk_bytes = 2 * r3_encoded_bytes(P) + pk_bytes + r3_encoded_bytes(P) + 32;
        let mut pk = vec![0u8; pk_bytes];
        let mut sk = vec![0u8; sk_bytes];
        let mut expander = NistSeedExpander::new(&seed);
        keypair_drbg::<P, Q>(&mut expander, &mut pk, &mut sk, W).unwrap();

        let h = Rq::<P, Q>::decode(&pk).unwrap();

        let r3_enc = r3_encoded_bytes(P);
        let f = R3::<P>::decode(&sk[..r3_enc]).unwrap();
        let grecip = R3::<P>::decode(&sk[r3_enc..2 * r3_enc]).unwrap();

        let mut f3 = Rq::<P, Q>::default();
        for i in 0..P {
            f3.0[i] = (3 * i32::from(f.0[i])) as i16;
        }

        let h_f3 = h.mul(&f3);

        let mut h_f3_mod3 = R3::<P>::default();
        for i in 0..P {
            h_f3_mod3.0[i] = mod3_freeze_i8(i32::from(h_f3.0[i]));
        }

        let check = h_f3_mod3.mul(&grecip);
        let mut ok = check.0[0] == 1;
        for i in 1..P {
            if check.0[i] != 0 {
                ok = false;
                break;
            }
        }
        assert!(ok, "h*(3*f) mod 3 * grecip != 1");
    }

    #[test]
    fn test_rq_recip3_simple_857() {
        const P: usize = 857;
        const Q: i16 = 5167;
        let one = R3::<P>::constant(1);
        let mut f_rq = Rq::<P, Q>::default();
        for i in 0..P {
            f_rq.0[i] = i16::from(one.0[i]);
        }
        let recip = rq_recip3::<P, Q>(&f_rq).unwrap();
        let mut f3_rq = Rq::<P, Q>::default();
        for i in 0..P {
            f3_rq.0[i] = (3 * i32::from(one.0[i])) as i16;
        }
        let prod = f3_rq.mul(&recip);
        if prod.0[0] != 1 {
            panic!(
                "rq_recip3 FAILS for P=857 Q=5167 f=1: prod[0]={}",
                prod.0[0]
            );
        }
        for i in 1..P {
            if prod.0[i] != 0 {
                panic!(
                    "rq_recip3 FAILS for P=857 Q=5167 f=1: prod[{}]={}",
                    i, prod.0[i]
                );
            }
        }
    }

    #[test]
    fn test_rq_recip3_real_f_857() {
        const P: usize = 857;
        const Q: i16 = 5167;
        const W: usize = 322;
        let pk_bytes = rq_encoded_bytes(P, Q);
        let sk_bytes = 2 * r3_encoded_bytes(P) + pk_bytes + r3_encoded_bytes(P) + 32;
        let mut pk = vec![0u8; pk_bytes];
        let mut sk = vec![0u8; sk_bytes];
        let mut expander = NistSeedExpander::new(&[0x42u8; 48]);
        keypair_drbg::<P, Q>(&mut expander, &mut pk, &mut sk, W).unwrap();
        let r3_enc = r3_encoded_bytes(P);
        let f = R3::<P>::decode(&sk[..r3_enc]).unwrap();
        assert_eq!(f.ct_weight(), W, "f weight should be {}", W);
        let mut f_rq = Rq::<P, Q>::default();
        for i in 0..P {
            f_rq.0[i] = i16::from(f.0[i]);
        }
        let recip = rq_recip3::<P, Q>(&f_rq).unwrap();
        let mut f3_rq = Rq::<P, Q>::default();
        for i in 0..P {
            f3_rq.0[i] = (3 * i32::from(f.0[i])) as i16;
        }
        let prod = f3_rq.mul(&recip);
        if prod.0[0] != 1 {
            panic!("rq_recip3 FAILS for REAL f: prod[0]={}", prod.0[0]);
        }
        let mut max_err = 0i16;
        for i in 1..P {
            if prod.0[i] != 0 {
                max_err = prod.0[i];
                break;
            }
        }
        if max_err != 0 {
            panic!("rq_recip3 FAILS for REAL f: max_error={}", max_err);
        }
    }

    #[test]
    fn test_full_roundtrip_857() {
        const P: usize = 857;
        const Q: i16 = 5167;
        const W: usize = 322;
        let seeds: &[[u8; 48]] = &[[1u8; 48], [2u8; 48]];
        let pk_bytes = rq_encoded_bytes(P, Q);
        let sk_bytes = 2 * r3_encoded_bytes(P) + pk_bytes + r3_encoded_bytes(P) + 32;
        let ct_bytes = rq_rounded_bytes(P, Q) + 32;
        let r_seed = [0x42u8; 32];
        for seed in seeds {
            let mut pk = vec![0u8; pk_bytes];
            let mut sk = vec![0u8; sk_bytes];
            let mut expander = NistSeedExpander::new(seed);
            keypair_drbg::<P, Q>(&mut expander, &mut pk, &mut sk, W).unwrap();
            let (ss, ct) = encaps::<P, Q>(&pk, &r_seed, W, ct_bytes).unwrap();
            let ss2 = decaps::<P, Q>(&sk, &ct, W).unwrap();
            assert_eq!(ss, ss2, "Full roundtrip failed for seed {:?}", seed);
        }
    }
}
