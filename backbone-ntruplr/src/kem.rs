#![allow(clippy::cast_sign_loss)]
// All casts in this module operate on bounded values (byte/limb extraction, loop counters).
//! NTRU LPRime KEM: key generation, encapsulation, decapsulation.
//!
//! Generic over ring dimension `P` and modulus `Q`.
//! Variant-specific constants are passed at call time.
//!
//! Reference: NTRU Prime (ntrulpr4591761) from ntruprime.cr.yp.to
//! Uses the same Rq/R3 ring as Streamlined NTRU Prime but constructs
//! the KEM via RLWE: pk = (seed_for_G, round3(G*a)), sk = a.

use crate::aes_ctr::aes256_ctr_fill;
use crate::error::Error;
use crate::poly::{modq_freeze, qshift, r3_encoded_bytes, rq_rounded_bytes, Rq, R3};
use alloc::vec;
use alloc::vec::Vec;
use backbone_pqcrypto_internals::nist_seed_expander::NistSeedExpander;
use backbone_pqcrypto_internals::secret::{SecretArray, SecretVec};
use sha2::{Digest, Sha512};
use subtle::{ConditionallySelectable, ConstantTimeEq};

fn modq_sum<const Q: i16>(a: i16, b: i16) -> i16 {
    modq_freeze::<Q>(i32::from(a) + i32::from(b))
}

fn modq_fromuint32<const Q: i16>(x: u32) -> i16 {
    let qs = qshift(Q);
    modq_freeze::<Q>(
        i32::try_from(x % u32::try_from(Q).expect("Q is positive")).expect("value fits in i32")
            - qs,
    )
}

fn uint32_minmax_pair(a: u32, b: u32) -> (u32, u32) {
    let xy = a ^ b;
    let mut c = b.wrapping_sub(a);
    c ^= xy & (c ^ b ^ 0x8000_0000);
    c >>= 31;
    c = 0u32.wrapping_sub(c);
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
            let mut i = 0usize;
            while i < n - q {
                if (i & p) == 0 {
                    let (a, b) = uint32_minmax_pair(values[i + p], values[i + q]);
                    values[i + p] = a;
                    values[i + q] = b;
                }
                i += 1;
            }
            q >>= 1;
        }

        p >>= 1;
    }
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

fn hash_confirm(inputs: &[u8; 32], cache: &[u8; 32]) -> [u8; 32] {
    let mut x = [0u8; 64];
    x[..32].copy_from_slice(inputs);
    x[32..].copy_from_slice(cache);
    hash_prefix(2, &x)
}

fn hash_session(prefix: u8, inputs: &[u8; 32], ct: &[u8]) -> [u8; 32] {
    let mut x = SecretVec::<u8>::new(32 + ct.len());
    x[..32].copy_from_slice(inputs);
    x[32..].copy_from_slice(ct);
    hash_prefix(prefix, &x)
}

fn rq_fromseed<const P: usize, const Q: i16>(seed: &[u8; 32]) -> Rq<P, Q> {
    let mut r = Rq::<P, Q>::default();
    let byte_len = P * 4;
    let mut buf = vec![0u8; byte_len];
    aes256_ctr_fill(seed, &mut buf);

    for i in 0..P {
        let word = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
        r.0[i] = modq_fromuint32::<Q>(word);
    }
    r
}

/// Generate a weight-w small polynomial from u32 words.
fn small_from_words<const P: usize>(words: &[u32], w: usize) -> R3<P> {
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

/// Generate a weight-w small polynomial from a seed.
fn small_seeded_weightw<const P: usize>(seed: &[u8; 32], w: usize) -> R3<P> {
    let byte_len = P * 4;
    let mut buf = SecretVec::<u8>::new(byte_len);
    aes256_ctr_fill(seed, buf.as_mut());

    let mut words = SecretVec::<u32>::new(P);
    for i in 0..P {
        words[i] = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
    }

    small_from_words::<P>(words.as_ref(), w)
}

const C_COUNT: usize = 256;

fn top<const TAU0: i32, const TAU1: i32>(c: i16) -> u8 {
    u8::try_from((TAU1 * (i32::from(c) + TAU0) + 16384) >> 15).expect("Top output fits in a nibble")
}

fn right<const Q: i16, const TAU2: i32, const TAU3: i32>(t: u8) -> i16 {
    modq_freeze::<Q>(TAU3 * i32::from(t) - TAU2)
}

fn pack_top(t: &[u8; C_COUNT]) -> [u8; 128] {
    let mut out = [0u8; 128];
    for i in 0..128 {
        out[i] = t[2 * i] | (t[2 * i + 1] << 4);
    }
    out
}

fn unpack_top(input: &[u8]) -> Result<[u8; C_COUNT], Error> {
    if input.len() < 128 {
        return Err(Error::InvalidCiphertextLength);
    }
    let mut t = [0u8; C_COUNT];
    for i in 0..128 {
        let byte = input[i];
        t[2 * i] = byte & 15;
        t[2 * i + 1] = byte >> 4;
    }
    Ok(t)
}

/// Generate an NTRU LPRime key pair from a 48-byte DRBG seed.
pub(crate) fn keypair_drbg<const P: usize, const Q: i16>(
    expander: &mut NistSeedExpander,
    pk: &mut [u8],
    sk: &mut [u8],
    w: usize,
) -> Result<(), Error> {
    let pk_bytes = rq_rounded_bytes(P, Q) + 32;
    let r3_enc = r3_encoded_bytes(P);

    if pk.len() != pk_bytes {
        return Err(Error::InvalidKeyLength);
    }
    if sk.len() != r3_enc + pk_bytes + 32 + 32 {
        return Err(Error::InvalidKeyLength);
    }

    let mut k_seed = [0u8; 32];
    expander.fill_bytes(&mut k_seed);

    let g = rq_fromseed::<P, Q>(&k_seed);

    let mut word_buf = [0u8; 4];
    let mut a_words = SecretVec::<u32>::new(P);
    for i in 0..P {
        expander.fill_bytes(&mut word_buf);
        a_words[i] = u32::from_le_bytes(word_buf);
    }
    let a = small_from_words::<P>(a_words.as_ref(), w);

    let ga = g.mul_small(&a);
    let a_poly = ga.round3();

    pk[..32].copy_from_slice(&k_seed);
    a_poly
        .encode_rounded(&mut pk[32..])
        .expect("rounded encoding failed");

    a.encode(&mut sk[..r3_enc])
        .expect("sk buffer is exactly r3_enc");
    sk[r3_enc..r3_enc + pk_bytes].copy_from_slice(pk);
    let rho_start = r3_enc + pk_bytes;
    expander.fill_bytes(&mut sk[rho_start..rho_start + 32]);
    let cache = hash_prefix(4, pk);
    sk[rho_start + 32..rho_start + 64].copy_from_slice(&cache);

    Ok(())
}

pub(crate) fn encaps<
    const P: usize,
    const Q: i16,
    const TAU0: i32,
    const TAU1: i32,
    const TAU2: i32,
    const TAU3: i32,
>(
    pk: &[u8],
    r: &[u8],
    w: usize,
    ct_bytes: usize,
) -> Result<([u8; 32], Vec<u8>), Error> {
    let pk_bytes = rq_rounded_bytes(P, Q) + 32;
    let rounded_bytes = rq_rounded_bytes(P, Q);
    if pk.len() != pk_bytes {
        return Err(Error::InvalidKeyLength);
    }
    if r.len() < 32 {
        return Err(Error::InvalidKeyLength);
    }
    if ct_bytes != rounded_bytes + 128 + 32 {
        return Err(Error::InvalidCiphertextLength);
    }
    let r_32: &[u8; 32] = r[..32].try_into().expect("length checked above");

    let k_seed: &[u8; 32] = pk[..32]
        .try_into()
        .expect("pk length validated before call");
    let g = rq_fromseed::<P, Q>(k_seed);
    let a = Rq::<P, Q>::decode_rounded(&pk[32..]).map_err(|_| Error::InvalidKeyLength)?;

    let b_seed = SecretArray::from_array(hash_prefix(5, r_32));
    let b = small_seeded_weightw::<P>(&b_seed, w);

    let gb = g.mul_small(&b);
    let b_poly = gb.round3();

    let ab = a.mul_small(&b);
    let qs = qshift(Q);
    let mut top_poly = [0u8; C_COUNT];
    for i in 0..C_COUNT {
        let bit = (r_32[i / 8] >> (i & 7)) & 1;
        let x = modq_sum::<Q>(
            ab.0[i],
            i16::try_from(qs).expect("qshift fits in i16") * i16::from(bit),
        );
        top_poly[i] = top::<TAU0, TAU1>(x);
    }

    let mut ct = vec![0u8; ct_bytes];
    b_poly
        .encode_rounded(&mut ct[..rounded_bytes])
        .expect("rounded encoding failed");
    ct[rounded_bytes..rounded_bytes + 128].copy_from_slice(&pack_top(&top_poly));
    let cache = hash_prefix(4, pk);
    let confirm = hash_confirm(r_32, &cache);
    ct[rounded_bytes + 128..].copy_from_slice(&confirm);

    let ss = hash_session(1, r_32, &ct);

    Ok((ss, ct))
}

pub(crate) fn decaps<
    const P: usize,
    const Q: i16,
    const TAU0: i32,
    const TAU1: i32,
    const TAU2: i32,
    const TAU3: i32,
>(
    sk: &[u8],
    ct: &[u8],
    w: usize,
) -> Result<[u8; 32], Error> {
    let r3_enc = r3_encoded_bytes(P);
    let rounded_bytes = rq_rounded_bytes(P, Q);
    let pk_bytes = rounded_bytes + 32;
    let expected_sk_len = r3_enc + pk_bytes + 32 + 32;
    let expected_ct_len = rounded_bytes + 128 + 32;

    if sk.len() != expected_sk_len {
        return Err(Error::InvalidSecretKeyLength);
    }
    if ct.len() != expected_ct_len {
        return Err(Error::InvalidCiphertextLength);
    }
    let a = R3::<P>::decode(&sk[..r3_enc]).map_err(|_| Error::InvalidSecretKeyLength)?;

    let b_poly = Rq::<P, Q>::decode_rounded(&ct[..rounded_bytes])
        .map_err(|_| Error::InvalidCiphertextLength)?;
    let top_poly = unpack_top(&ct[rounded_bytes..rounded_bytes + 128])?;

    let a_b = b_poly.mul_small(&a);

    let mut r = SecretArray::<u8, 32>::new();
    let threshold = 4 * i32::try_from(w).expect("w fits in i32") + 1;
    for i in 0..C_COUNT {
        let diff = i32::from(right::<Q, TAU2, TAU3>(top_poly[i])) - i32::from(a_b.0[i]);
        let val = modq_freeze::<Q>(diff + threshold);
        r[i / 8] |= ((val as u32 >> 31) as u8 & 1) << (i & 7);
    }

    let b_check_seed = SecretArray::from_array(hash_prefix(5, r.as_ref()));
    let b_check = small_seeded_weightw::<P>(&b_check_seed, w);

    let pk = &sk[r3_enc..r3_enc + pk_bytes];
    let rho: &[u8; 32] = sk[r3_enc + pk_bytes..r3_enc + pk_bytes + 32]
        .try_into()
        .expect("rho length checked by sk length");
    let cache: &[u8; 32] = sk[r3_enc + pk_bytes + 32..r3_enc + pk_bytes + 64]
        .try_into()
        .expect("cache length checked by sk length");
    let k_seed: &[u8; 32] = pk[..32]
        .try_into()
        .expect("pk slice derived from valid sk length");
    let g = rq_fromseed::<P, Q>(k_seed);
    let a_pk = Rq::<P, Q>::decode_rounded(&pk[32..]).map_err(|_| Error::InvalidSecretKeyLength)?;

    let gb_check = g.mul_small(&b_check);
    let b_check_poly = gb_check.round3();

    let qs = qshift(Q);
    let ab_check = a_pk.mul_small(&b_check);
    let mut top_check = SecretArray::<u8, C_COUNT>::new();
    for i in 0..C_COUNT {
        let bit = (r[i / 8] >> (i & 7)) & 1;
        let x = modq_sum::<Q>(
            ab_check.0[i],
            i16::try_from(qs).expect("qs fits in i16") * i16::from(bit),
        );
        top_check[i] = top::<TAU0, TAU1>(x);
    }

    let mut expected_ct = vec![0u8; expected_ct_len];
    b_check_poly
        .encode_rounded(&mut expected_ct[..rounded_bytes])
        .expect("rounded encoding failed");
    expected_ct[rounded_bytes..rounded_bytes + 128].copy_from_slice(&pack_top(&top_check));
    let confirm = hash_confirm(&r, cache);
    expected_ct[rounded_bytes + 128..].copy_from_slice(&confirm);

    let fail = ct.ct_ne(&expected_ct);
    for i in 0..32 {
        let tmp = u8::conditional_select(&r[i], &rho[i], fail);
        r[i] = tmp;
    }

    Ok(hash_session(1 - fail.unwrap_u8(), &r, ct))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss
    )]
    use super::*;

    const P: usize = 761;
    const Q: i16 = 4591;
    const W: usize = 250;
    const TAU0: i32 = 2156;
    const TAU1: i32 = 114;
    const TAU2: i32 = 2007;
    const TAU3: i32 = 287;
    const PK_BYTES: usize = 1039;
    const SK_BYTES: usize = 1294;
    const CT_BYTES: usize = 1167;

    #[test]
    fn test_rq_fromseed_deterministic() {
        let seed = [0x42u8; 32];
        let g1 = rq_fromseed::<P, Q>(&seed);
        let g2 = rq_fromseed::<P, Q>(&seed);
        assert_eq!(g1, g2);
    }

    #[test]
    fn test_rq_fromseed_nonzero() {
        let seed = [0x42u8; 32];
        let g = rq_fromseed::<P, Q>(&seed);
        assert!(g.0.iter().any(|&c| c != 0));
    }

    #[test]
    fn test_small_seeded_weightw_deterministic() {
        let seed = [0x12u8; 32];
        let f1 = small_seeded_weightw::<P>(&seed, W);
        let f2 = small_seeded_weightw::<P>(&seed, W);
        assert_eq!(f1, f2);
    }

    #[test]
    fn test_pack_unpack_top() {
        let mut c = [0u8; C_COUNT];
        for i in 0..C_COUNT {
            c[i] = (i % 16) as u8;
        }
        let packed = pack_top(&c);
        let unpacked = unpack_top(&packed).unwrap();
        for i in 0..C_COUNT {
            assert_eq!(unpacked[i], (i % 16) as u8, "mismatch at {}", i);
        }
    }

    #[test]
    fn test_keygen_roundtrip() {
        let mut expander = NistSeedExpander::new(&[0x42u8; 48]);
        let mut pk = vec![0u8; PK_BYTES];
        let mut sk = vec![0u8; SK_BYTES];
        keypair_drbg::<P, Q>(&mut expander, &mut pk, &mut sk, W).unwrap();

        assert_eq!(pk.len(), PK_BYTES);
        assert_eq!(sk.len(), SK_BYTES);
        assert!(pk.iter().any(|&b| b != 0));
        assert!(sk.iter().any(|&b| b != 0));

        let r = [0x13u8; 32];
        let (ss_enc, ct) = encaps::<P, Q, TAU0, TAU1, TAU2, TAU3>(&pk, &r, W, CT_BYTES).unwrap();
        let ss_dec = decaps::<P, Q, TAU0, TAU1, TAU2, TAU3>(&sk, &ct, W).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }
}
