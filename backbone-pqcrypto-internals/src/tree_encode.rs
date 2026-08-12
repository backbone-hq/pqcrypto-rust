//! Recursive tree encoding utilities for KAT test vector generation.
//!
//! Secret-carrying buffers are wrapped in `SecretVec` so the encoded secret
//! polynomials (used for f, grecip, r in sntrup/ntruplr) are zeroized on drop.
//! Moduli vectors (`mods`/`next_mods`) are public constants and stay plain.

use crate::secret::SecretVec;
use alloc::vec;
use alloc::vec::Vec;
use zeroize::Zeroize;

const TREE_LIMIT: u64 = 16384;

/// Exact number of bytes `rounded_encode` will produce for the given moduli
/// sequence. Mirrors the byte-push loops exactly, so the pre-sized output
/// buffer is fully consumed.
fn encoded_len(mods: &[u64]) -> usize {
    let mut mods = mods.to_vec();
    let mut total = 0usize;

    while mods.len() > 1 {
        let mut next = Vec::with_capacity(mods.len() / 2 + 1);
        let mut i = 0;
        while i + 1 < mods.len() {
            let mut cm = mods[i] * mods[i + 1];
            while cm >= TREE_LIMIT {
                total += 1;
                cm = (cm + 255) >> 8;
            }
            next.push(cm);
            i += 2;
        }
        if i < mods.len() {
            next.push(mods[i]);
        }
        mods = next;
    }

    if let Some(&m0) = mods.first() {
        let mut m = m0;
        while m > 1 {
            total += 1;
            m = (m + 255) >> 8;
        }
    }
    total
}

/// Encode a list of values and moduli into a byte vector.
///
/// `values` holds the (possibly secret) polynomial coefficients; `mods` are
/// the public moduli. The returned buffer is zeroized on drop.
#[must_use]
pub fn rounded_encode(mut values: SecretVec<u64>, mut mods: Vec<u64>) -> SecretVec<u8> {
    let total = encoded_len(&mods);
    let mut out = SecretVec::<u8>::new(total);
    let mut out_pos = 0usize;

    while mods.len() > 1 {
        let mut next_vals = SecretVec::<u64>::new(mods.len() / 2 + 1);
        let mut next_mods = Vec::with_capacity(mods.len() / 2 + 1);
        let mut nv = 0usize;

        let mut i = 0;
        while i + 1 < mods.len() {
            let m = mods[i] * mods[i + 1];
            let mut r = values[i] + mods[i] * values[i + 1];
            let mut cm = m;
            while cm >= TREE_LIMIT {
                out[out_pos] = (r & 0xFF) as u8;
                out_pos += 1;
                r >>= 8;
                cm = (cm + 255) >> 8;
            }
            next_vals[nv] = r;
            next_mods.push(cm);
            nv += 1;
            i += 2;
        }
        if i < mods.len() {
            next_vals[nv] = values[i];
            next_mods.push(mods[i]);
        }

        values.zeroize();
        values = next_vals;
        mods = next_mods;
    }

    if !mods.is_empty() {
        let mut r = values[0];
        let mut m = mods[0];
        while m > 1 {
            out[out_pos] = (r & 0xFF) as u8;
            out_pos += 1;
            r >>= 8;
            m = (m + 255) >> 8;
        }
    }

    values.zeroize();
    debug_assert_eq!(
        out_pos, total,
        "encoded byte count must match precomputed size"
    );
    out
}

/// Decode a byte vector back into values for the given moduli.
///
/// Returns `None` if the input is truncated (too short for the requested
/// modulus and count). The returned values buffer is zeroized on drop.
#[must_use]
pub fn rounded_decode(input: &[u8], m_val: u64, count: usize) -> Option<SecretVec<u64>> {
    fn decode_rec(input: &[u8], idx: &mut usize, mods: &[u64]) -> Option<SecretVec<u64>> {
        if mods.is_empty() {
            return Some(SecretVec::new(0));
        }
        if mods.len() == 1 {
            let mut val = 0u64;
            let mut shift = 0u8;
            let mut m = mods[0];
            while m > 1 {
                if *idx >= input.len() {
                    return None;
                }
                val |= u64::from(input[*idx]) << shift;
                *idx += 1;
                shift += 8;
                m = (m + 255) >> 8;
            }
            let mut out = SecretVec::<u64>::new(1);
            out[0] = val % mods[0];
            return Some(out);
        }

        let mut bottom = SecretVec::<(u64, u64)>::new(mods.len() / 2);
        let mut next_mods = Vec::with_capacity(mods.len() / 2 + 1);

        let mut i = 0;
        while i + 1 < mods.len() {
            let mut m = mods[i] * mods[i + 1];
            let mut r = 0u64;
            let mut t = 1u64;
            while m >= TREE_LIMIT {
                if *idx < input.len() {
                    r += u64::from(input[*idx]) * t;
                }
                *idx += 1;
                t <<= 8;
                m = (m + 255) >> 8;
            }
            bottom[i / 2] = (r, t);
            next_mods.push(m);
            i += 2;
        }
        if i < mods.len() {
            next_mods.push(mods[i]);
        }

        let high = decode_rec(input, idx, &next_mods)?;

        let mut result = SecretVec::<u64>::new(mods.len());
        let mut result_pos = 0usize;
        let mut hi = 0;
        let mut bi = 0;
        let mut i = 0;
        while i + 1 < mods.len() {
            let (r, t) = bottom[bi];
            bi += 1;
            let combined = r + t * high[hi];
            hi += 1;
            result[result_pos] = combined % mods[i];
            result_pos += 1;
            let shifted = combined / mods[i];
            result[result_pos] = shifted % mods[i + 1];
            result_pos += 1;
            i += 2;
        }
        if i < mods.len() {
            result[result_pos] = high[hi];
        }

        Some(result)
    }

    let mods = vec![m_val; count];
    let mut idx = 0;
    decode_rec(input, &mut idx, &mods)
}
