#![allow(clippy::cast_possible_truncation)]
// All casts in this module operate on bounded values (byte/limb extraction, loop counters).
pub(crate) use sha3::digest::{ExtendableOutput, Update, XofReader};

pub(crate) type Gf = u16;
pub(crate) type Vec64 = u64;

pub(crate) fn vec_setbits(bit: u64) -> Vec64 {
    0u64.wrapping_sub(bit)
}

fn load_window(mat: &[u64], nblocks_h: usize, row: usize, word_lo: usize, shift: usize) -> u64 {
    let base = row * nblocks_h;
    if shift == 0 {
        mat[base + word_lo]
    } else {
        (mat[base + word_lo] >> shift) | (mat[base + word_lo + 1] << (64 - shift))
    }
}

fn store_window(
    mat: &mut [u64],
    nblocks_h: usize,
    row: usize,
    word_lo: usize,
    shift: usize,
    val: u64,
) {
    let base = row * nblocks_h;
    if shift == 0 {
        mat[base + word_lo] = val;
    } else {
        let keep_lo = (1u64 << shift) - 1;
        let keep_hi = !keep_lo;
        mat[base + word_lo] = (mat[base + word_lo] & keep_lo) | (val << shift);
        mat[base + word_lo + 1] = (mat[base + word_lo + 1] & keep_hi) | (val >> (64 - shift));
    }
}

fn same_mask(x: u16, y: u16) -> u64 {
    let mask = u64::from(x ^ y);
    let mask = mask.wrapping_sub(1);
    let mask = mask >> 63;
    mask.wrapping_neg()
}

pub(crate) fn mov_columns(
    mat: &mut [u64],
    nblocks_h: usize,
    pk_nrows: usize,
    pi: &mut [i16],
) -> Result<u64, ()> {
    let row = pk_nrows - 32;
    let word_lo = (pk_nrows - 32) / 64;
    let shift = (pk_nrows - 32) % 64;

    let mut buf = [0u64; 64];
    for i in 0..32 {
        buf[i] = load_window(mat, nblocks_h, row + i, word_lo, shift);
    }

    let mut ctz_list = [0u32; 32];
    let mut pivots = 0u64;
    for i in 0..32 {
        let mut t = buf[i];
        for j in (i + 1)..32 {
            t |= buf[j];
        }
        if t == 0 {
            return Err(());
        }
        let s = t.trailing_zeros();
        ctz_list[i] = s;
        pivots |= 1u64 << s;

        for j in (i + 1)..32 {
            let mask = ((buf[i] >> s) & 1).wrapping_sub(1);
            buf[i] ^= buf[j] & mask;
        }
        for j in (i + 1)..32 {
            let mask = 0u64.wrapping_sub((buf[j] >> s) & 1);
            buf[j] ^= buf[i] & mask;
        }
    }

    for j in 0..32 {
        for k in (j + 1)..64 {
            let d = (pi[row + j] ^ pi[row + k]) & same_mask(k as u16, ctz_list[j] as u16) as i16;
            pi[row + j] ^= d;
            pi[row + k] ^= d;
        }
    }

    for i in 0..pk_nrows {
        let mut t = load_window(mat, nblocks_h, i, word_lo, shift);
        for j in 0..32 {
            let d = ((t >> j) ^ (t >> ctz_list[j])) & 1;
            t ^= d << ctz_list[j];
            t ^= d << j;
        }
        store_window(mat, nblocks_h, i, word_lo, shift, t);
    }

    Ok(pivots)
}
