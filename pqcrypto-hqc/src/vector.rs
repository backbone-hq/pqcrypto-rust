//! Vector operations for HQC: fixed-weight sampling, random vectors, add, compare, resize.
//! Vectors are bit-vectors stored as arrays of u64 limbs.

use crate::params::Params;
use alloc::vec;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

fn compare_u32(v1: u32, v2: u32) -> u32 {
    1 ^ (((v1.wrapping_sub(v2)) | (v2.wrapping_sub(v1))) >> 31)
}

fn write_support_to_vector(v: &mut [u64], support: &[u32], weight: usize) {
    let mut index_tab = vec![0u32; weight];
    let mut bit_tab = vec![0u64; weight];

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

/// Constant-time keygen fixed-weight sampler.
///
/// Generates 4·OMEGA random bytes from the XOF and delegates to
/// `vect_set_random_fixed_weight` (Algorithm 5), which uses a fixed-iteration
/// sort-based method with no secret-dependent rejection loops.
pub(crate) fn vect_set_random_fixed_weight_keygen_from_xof<P: Params, R: XofReader>(
    reader: &mut R,
    v: &mut [u64],
) {
    let mut rand_bytes = vec![0u8; 4 * P::OMEGA];
    reader.read(&mut rand_bytes);
    vect_set_random_fixed_weight::<P>(&rand_bytes, v, P::OMEGA);
}

pub(crate) fn vect_set_random_fixed_weight_keygen<P: Params>(seed: &[u8], v: &mut [u64]) {
    let mut hash = Shake256::default();
    hash.update(seed);
    hash.update(&[crate::kem::XOF_DOMAIN]);
    let mut reader = hash.finalize_xof();
    vect_set_random_fixed_weight_keygen_from_xof::<P, _>(&mut reader, v);
}

/// Generate a random vector with exactly `weight` nonzero bits (fixed Hamming weight).
/// Uses Algorithm 5 from https://eprint.iacr.org/2021/1631.pdf.
/// `rand_bytes` must have at least `4 * weight` bytes.
pub(crate) fn vect_set_random_fixed_weight<P: Params>(
    rand_bytes: &[u8],
    v: &mut [u64],
    weight: usize,
) {
    let mut support = vec![0u32; weight];
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

/// Generate a random vector (each bit independently uniform).
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
