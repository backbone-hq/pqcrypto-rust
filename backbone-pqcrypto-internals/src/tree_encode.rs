use alloc::vec;
use alloc::vec::Vec;
use zeroize::Zeroize;

// Reference: https://ntruprime.cr.yp.to/ntruprime-20200930.sage
//
// Encode(R, M) converts values R[i] in [0, M[i]) to a byte string using a
// binary-tree product encoding.  Decode(S, M) is the inverse.
//
// The caller supplies the VALUES (already normalised to [0, m_val)) and the
// MODULI (all equal to m_val).  The tree progresses level by level:
//   1. Pair adjacent entries; for each pair output ceil(log_256(m^2/LIMIT))
//      low bytes (where LIMIT = 16384).
//   2. The reduced combined value and modulus form the next level's entries.
//   3. Recurse until one entry remains (base case).

const TREE_LIMIT: u64 = 16384;

/// Encode a list of values and moduli into a byte vector.
#[must_use]
pub fn rounded_encode(mut values: Vec<u64>, mut mods: Vec<u64>) -> Vec<u8> {
    let mut out = Vec::new();

    while mods.len() > 1 {
        let mut next_vals = Vec::with_capacity(mods.len() / 2 + 1);
        let mut next_mods = Vec::with_capacity(mods.len() / 2 + 1);

        let mut i = 0;
        while i + 1 < mods.len() {
            let m = mods[i] * mods[i + 1];
            let mut r = values[i] + mods[i] * values[i + 1];
            let mut cm = m;
            while cm >= TREE_LIMIT {
                out.push((r & 0xFF) as u8);
                r >>= 8;
                cm = (cm + 255) >> 8;
            }
            next_vals.push(r);
            next_mods.push(cm);
            i += 2;
        }
        if i < mods.len() {
            next_vals.push(values[i]);
            next_mods.push(mods[i]);
        }

        values.zeroize();
        values = next_vals;
        mods = next_mods;
    }

    // Base case: one entry
    if !mods.is_empty() {
        let mut r = values[0];
        let mut m = mods[0];
        while m > 1 {
            out.push((r & 0xFF) as u8);
            r >>= 8;
            m = (m + 255) >> 8;
        }
    }

    values.zeroize();
    out
}

/// Decode a byte vector back into values for the given moduli.
///
/// Returns `None` if the input is truncated (too short for the requested
/// modulus and count).
#[must_use]
pub fn rounded_decode(input: &[u8], m_val: u64, count: usize) -> Option<Vec<u64>> {
    fn decode_rec(input: &[u8], idx: &mut usize, mods: &[u64]) -> Option<Vec<u64>> {
        if mods.is_empty() {
            return Some(Vec::new());
        }
        if mods.len() == 1 {
            let mut val = 0u64;
            let mut shift = 0u8;
            let mut m = mods[0];
            while m > 1 {
                if *idx >= input.len() {
                    return None; // truncated
                }
                val |= u64::from(input[*idx]) << shift;
                *idx += 1;
                shift += 8;
                m = (m + 255) >> 8;
            }
            return Some(vec![val % mods[0]]);
        }

        // First pass: read the low bytes for each pair
        let mut bottom: Vec<(u64, u64)> = Vec::with_capacity(mods.len() / 2);
        let mut next_mods: Vec<u64> = Vec::with_capacity(mods.len() / 2 + 1);

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
            bottom.push((r, t));
            next_mods.push(m);
            i += 2;
        }
        if i < mods.len() {
            next_mods.push(mods[i]);
        }

        // Recurse to get the high parts
        let high = decode_rec(input, idx, &next_mods)?;

        // Second pass: combine low + high, split into pairs
        let mut result = Vec::with_capacity(mods.len());
        let mut hi = 0;
        let mut bi = 0;
        let mut i = 0;
        while i + 1 < mods.len() {
            let (r, t) = bottom[bi];
            bi += 1;
            let combined = r + t * high[hi];
            hi += 1;
            result.push(combined % mods[i]);
            let shifted = combined / mods[i];
            result.push(shifted % mods[i + 1]);
            i += 2;
        }
        if i < mods.len() {
            result.push(high[hi]);
        }

        Some(result)
    }

    let mods = vec![m_val; count];
    let mut idx = 0;
    decode_rec(input, &mut idx, &mods)
}
