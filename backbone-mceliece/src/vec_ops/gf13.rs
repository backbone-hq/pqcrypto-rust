// GFBITS=13 specific vector operations (vec_mul, vec_sq, vec_inv)
use crate::common::*;

const GFBITS: usize = 13;

pub(crate) fn vec_mul(out: &mut [Vec64; GFBITS], f: &[Vec64; GFBITS], g: &[Vec64; GFBITS]) {
    let mut buf = [0u64; 2 * GFBITS - 1];
    for i in 0..GFBITS {
        for j in 0..GFBITS {
            buf[i + j] ^= f[i] & g[j];
        }
    }
    for i in (GFBITS..=(2 * GFBITS - 2)).rev() {
        buf[i - GFBITS + 4] ^= buf[i];
        buf[i - GFBITS + 3] ^= buf[i];
        buf[i - GFBITS + 1] ^= buf[i];
        buf[i - GFBITS] ^= buf[i];
    }
    out.copy_from_slice(&buf[..GFBITS]);
}

pub(crate) fn vec_sq(out: &mut [Vec64; GFBITS], input: &[Vec64; GFBITS]) {
    let t = input[11] ^ input[12];
    let result = [
        input[0] ^ input[11],
        input[7] ^ t,
        input[1] ^ input[7],
        input[8] ^ t,
        input[2] ^ input[7] ^ input[8] ^ t,
        input[7] ^ input[9],
        input[3] ^ input[8] ^ input[9] ^ input[12],
        input[8] ^ input[10],
        input[4] ^ input[9] ^ input[10],
        input[9] ^ input[11],
        input[5] ^ input[10] ^ input[11],
        input[10] ^ input[12],
        input[6] ^ t,
    ];
    out.copy_from_slice(&result);
}

pub(crate) fn vec_inv(out: &mut [Vec64; GFBITS], input: &[Vec64; GFBITS]) {
    let mut tmp_11 = [0u64; GFBITS];
    let mut tmp_1111 = [0u64; GFBITS];
    out.copy_from_slice(input);
    let snapshot = *out;
    vec_sq(out, &snapshot);
    let snapshot = *out;
    vec_mul(&mut tmp_11, &snapshot, input);
    vec_sq(out, &tmp_11);
    let snapshot = *out;
    vec_sq(out, &snapshot);
    let snapshot = *out;
    vec_mul(&mut tmp_1111, &snapshot, &tmp_11);
    vec_sq(out, &tmp_1111);
    let snapshot = *out;
    vec_sq(out, &snapshot);
    let snapshot = *out;
    vec_sq(out, &snapshot);
    let snapshot = *out;
    vec_sq(out, &snapshot);
    let snapshot = *out;
    vec_mul(out, &snapshot, &tmp_1111);
    let snapshot = *out;
    vec_sq(out, &snapshot);
    let snapshot = *out;
    vec_sq(out, &snapshot);
    let snapshot = *out;
    vec_sq(out, &snapshot);
    let snapshot = *out;
    vec_sq(out, &snapshot);
    let snapshot = *out;
    vec_mul(out, &snapshot, &tmp_1111);
    let snapshot = *out;
    vec_sq(out, &snapshot);
}
