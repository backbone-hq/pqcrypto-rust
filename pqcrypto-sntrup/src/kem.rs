//! SNTRUP KEM: key generation, encapsulation, decapsulation.
//!
//! Generic over ring dimension `P` and modulus `Q`.
//! Variant-specific constants (weight `w`, ciphertext size `ct_bytes`) are
//! passed at call time.

use crate::poly::{r3_encoded_bytes, rq_encoded_bytes, rq_rounded_bytes, Rq, R3};
use alloc::vec;
use alloc::vec::Vec;
use pqcrypto_utils::secret::SecretVec;
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

fn prng_label(seed: &[u8], label: u8, counter: u32, out: &mut [u8]) {
    let mut shake = Shake256::default();
    shake.update(seed);
    shake.update(&[label]);
    shake.update(&counter.to_le_bytes());
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
    let mut x = Vec::with_capacity(64);
    x.extend_from_slice(&h3);
    x.extend_from_slice(cache);
    hash_prefix(2, &x)
}

fn hash_session(prefix: u8, inputs: &[u8], ct: &[u8]) -> [u8; 32] {
    let h3 = hash_prefix(3, inputs);
    let mut x = Vec::with_capacity(32 + ct.len());
    x.extend_from_slice(&h3);
    x.extend_from_slice(ct);
    hash_prefix(prefix, &x)
}

fn uint32_minmax_pair(a: u32, b: u32) -> (u32, u32) {
    let mut c = b.wrapping_sub(a);
    c >>= 31;
    c = 0u32.wrapping_sub(c);
    c &= a ^ b;
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

        let mut i = 0usize;
        let mut q = top;
        while q > p {
            while i < n - q {
                if (i & p) == 0 {
                    let mut a = values[i + p];
                    let mut r = q;
                    while r > p {
                        let (lo, hi) = uint32_minmax_pair(a, values[i + r]);
                        a = lo;
                        values[i + r] = hi;
                        r >>= 1;
                    }
                    values[i + p] = a;
                }
                i += 1;
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

/// Compute s^(-1) in R3 = GF(3)[x]/(x^p - x - 1).
/// Returns Ok(r) if s is invertible, Err(()) otherwise.
pub(crate) fn r3_recip<const P: usize>(s: &R3<P>) -> Result<R3<P>, ()> {
    let loops = 2 * P + 1;

    // f = x^p - x - 1 (the modulus)
    let mut f = SecretVec::<i8>::new(P + 1);
    f[0] = -1;
    f[1] = -1;
    f[P] = 1;

    // g = s (input polynomial)
    let mut g = SecretVec::<i8>::new(P + 1);
    for i in 0..P {
        g[i] = s.0[i];
    }

    // u = 0, v = 1
    let mut u = SecretVec::<i8>::new(loops + 1);
    let mut v = SecretVec::<i8>::new(loops + 1);
    v[0] = 1;

    let mut d = i32::try_from(P).expect("P fits in i32");
    let mut e = i32::try_from(P).expect("P fits in i32");

    for loop_idx in 0..loops {
        // c = g[p] / f[p]  (leading coefficient quotient in GF(3))
        let c = mod3_quotient(g[P], f[P]);

        // g = g - c * f, then shift right
        for i in 0..=P {
            g[i] = mod3_minusproduct(g[i], f[i], c);
        }
        // shift g right (optimized memmove)
        g.copy_within(0..P, 1);
        g[0] = 0;

        // v = v - c * u, then shift right
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

        // Conditional swap if e < d AND g[p] != 0
        let smaller_mask = (e - d) >> 31;
        let swapmask = smaller_mask & mod3_nonzero_mask(g[P]);

        // Constant-time swap using arithmetic masking (no branch on secret data)
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
        // C incs loop before swap check, so use loop_idx+1
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

    // Normalize result
    let c = mod3_reciprocal(f[P]);
    let mut result = R3::<P>::default();
    for i in 0..P {
        result.0[i] = mod3_product(u[P + i], c);
    }

    // Verify: s * r = 1 mod (x^p - x - 1)
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

/// Rq reciprocal: compute 1/(3*f) in Rq = (Z/qZ)[x]/(x^p - x - 1)
fn rq_recip3<const P: usize, const Q: i16>(f3: &Rq<P, Q>) -> Result<Rq<P, Q>, ()> {
    let loops = 2 * P + 1;

    // f = x^p - x - 1 (the modulus)
    let mut f = SecretVec::<i32>::new(P + 1);
    f[0] = -1;
    f[1] = -1;
    f[P] = 1;

    // g = 3 * input (since we want recip of 3*f3)
    let mut g = SecretVec::<i32>::new(P + 1);
    for i in 0..P {
        g[i] = 3 * i32::from(f3.0[i]);
    }
    g[P] = 0;

    // u = 0, v = 1
    let mut u = SecretVec::<i32>::new(loops + 1);
    let mut v = SecretVec::<i32>::new(loops + 1);
    v[0] = 1;

    let mut d = i32::try_from(P).expect("P fits in i32");
    let mut e = i32::try_from(P).expect("P fits in i32");

    for loop_idx in 0..loops {
        // c = g[p] / f[p]  (leading coefficient quotient in GF(q))
        let c = modq_divide::<Q>(g[P], f[P]);

        // g = g - c * f, then shift right
        for i in 0..=P {
            g[i] = modq_sub::<Q>(g[i], modq_mul::<Q>(c, f[i]));
        }
        g.copy_within(0..P, 1);
        g[0] = 0;

        // v = v - c * u, then shift right
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

        // Conditional swap if e < d AND g[p] != 0
        let smaller_mask = (e - d) >> 31;
        let swapmask = smaller_mask & modq_nonzero_mask::<Q>(g[P]);

        // Constant-time swap using arithmetic masking (no branch on secret data)
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
        // Same loop-offset as r3_recip: C increments loop before swap
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

    // Result = 1/f[p] * u[p..2p]
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
    // Extended Euclidean algorithm for modular inverse
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

fn words_from_seed<const P: usize>(seed: &[u8]) -> Vec<u32> {
    let rand_bytes_len = 4 * P;
    let mut rnd = vec![0u8; rand_bytes_len];
    prng(seed, &mut rnd);
    rnd.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn short_from_words<const P: usize>(words: &[u32], w: usize) -> R3<P> {
    let mut list = vec![0u32; P];
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
    short_from_words::<P>(&words_from_seed::<P>(seed), w)
}

fn random_small<const P: usize>(seed: &[u8]) -> R3<P> {
    let words = words_from_seed::<P>(seed);
    let mut poly = R3::<P>::default();
    for i in 0..P {
        let v = (((u64::from(words[i] & 0x3fff_ffff)) * 3) >> 30) as i8;
        poly.0[i] = v - 1;
    }
    poly
}

/// Generate a keypair.
pub(crate) fn keypair<const P: usize, const Q: i16>(
    pk: &mut [u8],
    sk: &mut [u8],
    seed: &[u8],
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

    let mut g_buf = SecretVec::<u8>::new(32);
    let mut attempt = 0u32;
    let (g, grecip) = loop {
        prng_label(seed, b'g', attempt, &mut g_buf);
        let g = random_small::<P>(&g_buf);
        if let Ok(grecip) = r3_recip::<P>(&g) {
            break (g, grecip);
        }
        attempt = attempt.wrapping_add(1);
    };

    let mut f_buf = SecretVec::<u8>::new(32);
    prng_label(seed, b'f', 0, &mut f_buf);
    let f = random_weightw::<P>(&f_buf, w);

    // Compute h = g / (3*f) in Rq
    let mut f_rq = Rq::<P, Q>::default();
    for i in 0..P {
        f_rq.0[i] = i16::from(f.0[i]);
    }
    let recip = rq_recip3::<P, Q>(&f_rq).map_err(|_| crate::error::Error::DecapsulationFailed)?;
    let mut g_rq = Rq::<P, Q>::default();
    for i in 0..P {
        g_rq.0[i] = i16::from(g.0[i]);
    }
    let h = recip.mul(&g_rq);

    // Encode outputs
    h.encode(pk)
        .map_err(|_| crate::error::Error::DecapsulationFailed)?;

    // SK: f || grecip || pk || rho || Hash4(pk)
    f.encode(&mut sk[..r3_enc])
        .expect("sk buffer is exactly r3_enc");
    grecip
        .encode(&mut sk[r3_enc..2 * r3_enc])
        .expect("sk buffer is exactly 2*r3_enc");
    let pk_start = 2 * r3_enc;
    sk[pk_start..pk_start + pk_bytes].copy_from_slice(pk);
    let rho_start = pk_start + pk_bytes;
    prng_label(seed, b'r', 0, &mut sk[rho_start..rho_start + r3_enc]);
    let cache = hash_prefix(4, pk);
    sk[rho_start + r3_enc..rho_start + r3_enc + 32].copy_from_slice(&cache);

    Ok(())
}

/// Encapsulate: generate shared secret and ciphertext.
pub(crate) fn encaps<const P: usize, const Q: i16>(
    pk: &[u8],
    r_seed: &[u8],
    w: usize,
    ct_bytes: usize,
) -> Result<([u8; 32], Vec<u8>), crate::error::Error> {
    let pk_bytes = rq_encoded_bytes(P, Q);
    let r3_enc = r3_encoded_bytes(P);
    let rounded_bytes = rq_rounded_bytes(P, Q);

    if pk.len() != pk_bytes {
        return Err(crate::error::Error::InvalidKeyLength);
    }

    let h = Rq::<P, Q>::decode(pk).map_err(|_| crate::error::Error::InvalidKeyLength)?;
    let r = random_weightw::<P>(r_seed, w);

    let mut r_enc = vec![0u8; r3_enc];
    r.encode(&mut r_enc)
        .expect("r_enc buffer is exactly r3_enc");

    // Compute c = Rounded(h * r)
    let hr = h.mul_small(&r);
    let mut c = Rq::<P, Q>::default();
    for i in 0..P {
        c.0[i] = hr.0[i]; // h*r in Rq
    }
    let rounded = c.round3();

    let mut ct = vec![0u8; ct_bytes];
    let rounded_enc = rounded.encode_rounded();
    if rounded_enc.len() != rounded_bytes || ct_bytes != rounded_bytes + 32 {
        return Err(crate::error::Error::InvalidCiphertextLength);
    }
    ct[..rounded_bytes].copy_from_slice(&rounded_enc);
    let cache = hash_prefix(4, pk);
    let confirm = hash_confirm(&r_enc, &cache);
    ct[rounded_bytes..].copy_from_slice(&confirm);

    let ss = hash_session(1, &r_enc, &ct);

    Ok((ss, ct))
}

/// Decapsulate: recover shared secret from ciphertext.
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

    // t = c * f in Rq
    let t = rounded_c.mul_small(&f);

    // t3 = 3 * t mod q, then reduce to R3
    let q = i32::from(Q);
    let qs = crate::poly::qshift(Q);
    let mut t3 = R3::<P>::default();
    for i in 0..P {
        let mut val = (3i32 * i32::from(t.0[i])) % q;
        if val > qs {
            val -= q;
        } else if val < -qs {
            val += q;
        }
        t3.0[i] = mod3_freeze_i8(val);
    }

    // r_recovered = t3 * grecip in R3
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
    let rounded_enc = cnew.encode_rounded();
    let mut expected_ct = vec![0u8; expected_ct_len];
    expected_ct[..rounded_bytes].copy_from_slice(&rounded_enc);
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
        // 1^(-1) = 1 in R3
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
        // f = 1 (the constant polynomial 1 in R3)
        let one = R3::<P>::constant(1);
        // Convert to Rq
        let mut f_rq = Rq::<P, Q>::default();
        for i in 0..P {
            f_rq.0[i] = i16::from(one.0[i]);
        }
        // rq_recip3 computes 1/(3*f) in Rq
        let recip = rq_recip3::<P, Q>(&f_rq).unwrap();
        // Verify: 3 * f * recip = 1 in Rq
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

    #[test]
    fn test_keygen_roundtrip() {
        let seed = [0x42u8; 32];
        let pk_bytes = rq_encoded_bytes(P, Q);
        let sk_bytes = 2 * r3_encoded_bytes(P) + pk_bytes + r3_encoded_bytes(P) + 32;
        let mut pk = vec![0u8; pk_bytes];
        let mut sk = vec![0u8; sk_bytes];
        keypair::<P, Q>(&mut pk, &mut sk, &seed, W).unwrap();
        assert_eq!(pk.len(), pk_bytes);
        assert_eq!(sk.len(), sk_bytes);
        assert!(pk.iter().any(|&b| b != 0));
        assert!(sk.iter().any(|&b| b != 0));

        // Test encaps/decaps roundtrip
        let r_seed = [0x13u8; 32];
        let (ss_enc, ct) = encaps::<P, Q>(&pk, &r_seed, W, CT_BYTES).unwrap();
        let ss_dec = decaps::<P, Q>(&sk, &ct, W).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_keygen_math() {
        let seed = [0x42u8; 32];
        let pk_bytes = rq_encoded_bytes(P, Q);
        let sk_bytes = 2 * r3_encoded_bytes(P) + pk_bytes + r3_encoded_bytes(P) + 32;
        let mut pk = vec![0u8; pk_bytes];
        let mut sk = vec![0u8; sk_bytes];
        keypair::<P, Q>(&mut pk, &mut sk, &seed, W).unwrap();

        // Decode h from pk
        let h = Rq::<P, Q>::decode(&pk).unwrap();

        // Decode f and grecip from sk
        let r3_enc = r3_encoded_bytes(P);
        let f = R3::<P>::decode(&sk[..r3_enc]).unwrap();
        let grecip = R3::<P>::decode(&sk[r3_enc..2 * r3_enc]).unwrap();

        // Compute 3*f in Rq
        let mut f3 = Rq::<P, Q>::default();
        for i in 0..P {
            f3.0[i] = (3 * i32::from(f.0[i])) as i16;
        }

        let h_f3 = h.mul(&f3); // h * (3*f) in Rq

        // Reduce to R3
        let mut h_f3_mod3 = R3::<P>::default();
        for i in 0..P {
            h_f3_mod3.0[i] = mod3_freeze_i8(i32::from(h_f3.0[i]));
        }

        // Multiply by grecip: (h * 3*f mod 3) * grecip should = 1
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
        // Generate a real keypair and verify rq_recip3 for its f
        const P: usize = 857;
        const Q: i16 = 5167;
        const W: usize = 322;
        let pk_bytes = rq_encoded_bytes(P, Q);
        let sk_bytes = 2 * r3_encoded_bytes(P) + pk_bytes + r3_encoded_bytes(P) + 32;
        let mut pk = vec![0u8; pk_bytes];
        let mut sk = vec![0u8; sk_bytes];
        keypair::<P, Q>(&mut pk, &mut sk, &[0x42u8; 32], W).unwrap();
        let r3_enc = r3_encoded_bytes(P);
        let f = R3::<P>::decode(&sk[..r3_enc]).unwrap();
        assert_eq!(f.ct_weight(), W, "f weight should be {}", W);
        let mut f_rq = Rq::<P, Q>::default();
        for i in 0..P {
            f_rq.0[i] = i16::from(f.0[i]);
        }
        // Delete the grecip from sk to test rq_recip3 specifically
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
        let seeds: &[&[u8]] = &[b"test_857_001", b"test_857_002"];
        let pk_bytes = rq_encoded_bytes(P, Q);
        let sk_bytes = 2 * r3_encoded_bytes(P) + pk_bytes + r3_encoded_bytes(P) + 32;
        let ct_bytes = rq_rounded_bytes(P, Q) + 32;
        let r_seed = [0x42u8; 32];
        for seed in seeds {
            let mut pk = vec![0u8; pk_bytes];
            let mut sk = vec![0u8; sk_bytes];
            keypair::<P, Q>(&mut pk, &mut sk, seed, W).unwrap();
            let (ss, ct) = encaps::<P, Q>(&pk, &r_seed, W, ct_bytes).unwrap();
            let ss2 = decaps::<P, Q>(&sk, &ct, W).unwrap();
            assert_eq!(ss, ss2, "Full roundtrip failed for seed {:?}", seed);
        }
    }
}
