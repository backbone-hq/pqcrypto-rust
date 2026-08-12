#![allow(clippy::cast_possible_truncation)]
// All casts in this module operate on bounded values (byte/limb extraction, loop counters).
//! Vector operations for HQC: fixed-weight sampling, random vectors, add, compare, resize.
//! Vectors are bit-vectors stored as arrays of u64 limbs.

use crate::params::Params;
use backbone_pqcrypto_internals::secret::SecretVec;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

fn compare_u32(v1: u32, v2: u32) -> u32 {
    1 ^ (((v1.wrapping_sub(v2)) | (v2.wrapping_sub(v1))) >> 31)
}

fn write_support_to_vector(v: &mut [u64], support: &[u32], weight: usize) {
    let mut index_tab = SecretVec::<u32>::new(weight);
    let mut bit_tab = SecretVec::<u64>::new(weight);

    for i in 0..weight {
        index_tab[i] = support[i] >> 6;
        bit_tab[i] = 1u64 << (support[i] & 0x3f);
    }

    for (i, limb) in v.iter_mut().enumerate() {
        let mut val = 0u64;
        for j in 0..weight {
            let tmp = (i as u32).wrapping_sub(index_tab[j]);
            let val1 = 1 ^ ((tmp | tmp.wrapping_neg()) >> 31);
            let mask = 0u64.wrapping_sub(u64::from(val1));
            val |= bit_tab[j] & mask;
        }
        *limb |= val;
    }
}

/// Constant-time keygen fixed-weight sampler (rejection sampling).
///
/// Mirrors the current FIPS 207 reference `vect_generate_random_support1`,
/// including its XOF stream consumption: 3-byte big-endian candidates
/// (`b0≪16 | b1≪8 | b2`) are read from a chunk of `3·ω` bytes, and each
/// refill consumes `ceil(3·ω/8)·8` bytes from the SHAKE stream (the
/// reference's `xof_get_bytes` squeezes 8-byte-aligned chunks and discards
/// the padding). The duplicate check is branchless (reference uses a
/// variable-time linear scan); both accept/reject identically.
pub(crate) fn vect_set_random_fixed_weight_keygen_from_xof<P: Params, R: XofReader>(
    reader: &mut R,
    v: &mut [u64],
) {
    v.fill(0);

    let n = P::N as u32;
    let mu = P::PARAM_N_MU;
    let threshold = P::REJECTION_THRESHOLD;

    let chunk_used = 3 * P::OMEGA;
    let chunk_read = chunk_used.div_ceil(8) * 8;
    let mut chunk = SecretVec::<u8>::new(chunk_read);
    let mut pos = chunk_used; // start exhausted → refill on the first candidate

    let mut count = 0usize;
    // Generous attempt bound (rejection is rare: threshold ≈ 2^24·(1−ε)).
    let max_iters = 16 * P::OMEGA * (chunk_read / chunk_used.max(1)).max(1);
    let mut iters = 0usize;

    while count < P::OMEGA && iters < max_iters {
        if pos == chunk_used {
            reader.read(&mut chunk[..chunk_read]);
            pos = 0;
        }
        iters += 1;

        let candidate = (u32::from(chunk[pos]) << 16)
            | (u32::from(chunk[pos + 1]) << 8)
            | u32::from(chunk[pos + 2]);
        pos += 3;

        if candidate < threshold {
            // Barrett reduction: constant-time mod N (reference barrett_reduce).
            let q = (u64::from(candidate) * u64::from(mu)) >> 32;
            let mut r = candidate - (q as u32) * n;
            let reduce_flag = ((r.wrapping_sub(n)) >> 31) ^ 1;
            let mask = reduce_flag.wrapping_neg();
            r -= mask & n;

            // Branchless duplicate check via bit-vector occupancy.
            let idx = (r >> 6) as usize;
            if idx < v.len() {
                let bit_mask = 1u64 << (r & 0x3f);
                let already_set = (v[idx] >> (r & 0x3f)) & 1;
                let is_new = 1u64.wrapping_sub(already_set);
                v[idx] |= bit_mask; // harmless when already set
                count += is_new as usize;
            }
        }
    }

    debug_assert_eq!(count, P::OMEGA, "rejection sampler hit attempt bound");
}

pub(crate) fn vect_set_random_fixed_weight_keygen<P: Params>(seed: &[u8], v: &mut [u64]) {
    let mut hash = Shake256::default();
    hash.update(seed);
    hash.update(&[crate::kem::XOF_DOMAIN]);
    let mut reader = hash.finalize_xof();
    vect_set_random_fixed_weight_keygen_from_xof::<P, _>(&mut reader, v);
}

/// Uses Algorithm 5 from https://eprint.iacr.org/2021/1631.pdf.
/// `rand_bytes` must have at least `4 * weight` bytes.
pub(crate) fn vect_set_random_fixed_weight<P: Params>(
    rand_bytes: &[u8],
    v: &mut [u64],
    weight: usize,
) {
    let mut support = SecretVec::<u32>::new(weight);
    for i in 0..weight {
        let val = u32::from(rand_bytes[4 * i])
            | u32::from(rand_bytes[4 * i + 1]) << 8
            | u32::from(rand_bytes[4 * i + 2]) << 16
            | u32::from(rand_bytes[4 * i + 3]) << 24;
        let remaining = u64::try_from(P::N - i).expect("N - i fits in u64");
        support[i] = u32::try_from(i).expect("i fits in u32")
            + (((u64::from(val) * remaining) >> 32) as u32);
    }

    for i in (0..weight.saturating_sub(1)).rev() {
        let mut found = 0u32;
        for j in i + 1..weight {
            found |= compare_u32(support[j], support[i]);
        }
        let mask = 0u32.wrapping_sub(found);
        support[i] = (mask & u32::try_from(i).expect("i fits in u32")) ^ (!mask & support[i]);
    }

    write_support_to_vector(v, &support, weight);
}

/// `rand_bytes` must have at least VEC_N_SIZE_BYTES bytes.
pub(crate) fn vect_set_random<P: Params>(rand_bytes: &[u8], v: &mut [u64]) {
    crate::parsing::load8_arr(v, rand_bytes);
    v[P::VEC_N_SIZE_64 - 1] &= P::RED_MASK;
}

/// XOR-add two vectors: `o[i] = v1[i] ^ v2[i]`
pub(crate) fn vect_add(o: &mut [u64], v1: &[u64], v2: &[u64], size: usize) {
    for i in 0..size {
        o[i] = v1[i] ^ v2[i];
    }
}
