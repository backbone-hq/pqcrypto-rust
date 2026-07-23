use crate::common::*;
use crate::decode;
use crate::vec_ops::gf12::*;
use alloc::vec;
use alloc::vec::Vec;
use backbone_pqcrypto_internals::secret::SecretArray;

pub(crate) const GFBITS: usize = 12;
pub(crate) const SYS_T: usize = 64;
pub(crate) const SYS_N: usize = 3488;
pub(crate) const PK_NROWS: usize = 768;
pub(crate) const PK_NCOLS: usize = 2720;
pub(crate) const PK_ROW_BYTES: usize = 340;
pub(crate) const SYND_BYTES: usize = 96;
pub(crate) const IRR_BYTES: usize = 128;
pub(crate) const COND_BYTES: usize = 5888;
pub(crate) const GFMASK: u16 = 4095u16;
pub(crate) const CRYPTO_PUBLICKEYBYTES: usize = 261120;
pub(crate) const CRYPTO_SECRETKEYBYTES: usize = 6492;
pub(crate) const CRYPTO_CIPHERTEXTBYTES: usize = 96;
pub(crate) const CRYPTO_BYTES: usize = 32;
pub(crate) fn shake256_into(output: &mut [u8], input: &[u8]) {
    let mut x = sha3::Shake256::default();
    x.update(input);
    x.finalize_xof().read(output);
}
/// Copy a bitsliced vector.
pub(crate) fn vec_copy(out: &mut [Vec64; GFBITS], inp: &[Vec64; GFBITS]) {
    out.copy_from_slice(inp);
}
fn load8(b: &[u8]) -> u64 {
    let len = b.len();
    if len >= 8 {
        u64::from(b[0])
            | (u64::from(b[1]) << 8)
            | (u64::from(b[2]) << 16)
            | (u64::from(b[3]) << 24)
            | (u64::from(b[4]) << 32)
            | (u64::from(b[5]) << 40)
            | (u64::from(b[6]) << 48)
            | (u64::from(b[7]) << 56)
    } else {
        let mut v = 0u64;
        for i in 0..len {
            v |= u64::from(b[i]) << (i * 8);
        }
        v
    }
}
/// Store a `u64` as 8 bytes in little-endian order.
pub(crate) fn store8(b: &mut [u8], v: u64) {
    b[0] = u8::try_from(v & 0xff).expect("byte 0 fits in u8");
    b[1] = u8::try_from((v >> 8) & 0xff).expect("byte 1 fits in u8");
    b[2] = u8::try_from((v >> 16) & 0xff).expect("byte 2 fits in u8");
    b[3] = u8::try_from((v >> 24) & 0xff).expect("byte 3 fits in u8");
    b[4] = u8::try_from((v >> 32) & 0xff).expect("byte 4 fits in u8");
    b[5] = u8::try_from((v >> 40) & 0xff).expect("byte 5 fits in u8");
    b[6] = u8::try_from((v >> 48) & 0xff).expect("byte 6 fits in u8");
    b[7] = u8::try_from((v >> 56) & 0xff).expect("byte 7 fits in u8");
}
pub(crate) fn load_gf(b: &[u8]) -> Gf {
    u16::from(b[0]) | (u16::from(b[1]) << 8)
}
/// Store a `Gf` value as 2 bytes (little-endian).
pub(crate) fn store_gf(b: &mut [u8], v: Gf) {
    b[0] = u8::try_from(v & 0xff).expect("gf low byte fits in u8");
    b[1] = u8::try_from((v >> 8) & 0xff).expect("gf high byte fits in u8");
}
pub(crate) fn load4(b: &[u8]) -> u64 {
    u64::from(b[0]) | (u64::from(b[1]) << 8) | (u64::from(b[2]) << 16) | (u64::from(b[3]) << 24)
}
/// Store the lower `i` bytes of `v` into `out` (little-endian).
fn store_i(out: &mut [u8], v: u64, i: usize) {
    for j in 0..i {
        out[j] = u8::try_from((v >> (j * 8)) & 0xff).expect("store_i byte fits in u8");
    }
}
pub(crate) fn radix_conversions(inp: &mut [Vec64; GFBITS], scalars: &[[u64; 12]; 5]) {
    const MASKS: [[u64; 2]; 5] = [
        [0x8888_8888_8888_8888, 0x4444_4444_4444_4444],
        [0xC0C0_C0C0_C0C0_C0C0, 0x3030_3030_3030_3030],
        [0xF000_F000_F000_F000, 0x0F00_0F00_0F00_0F00],
        [0xFF00_0000_FF00_0000, 0x00FF_0000_00FF_0000],
        [0xFFFF_0000_0000_0000, 0x0000_FFFF_0000_0000],
    ];
    for j in 0..=4 {
        for i in 0..GFBITS {
            for k in (j..=4).rev() {
                inp[i] ^= (inp[i] & MASKS[k][0]) >> (1 << k);
                inp[i] ^= (inp[i] & MASKS[k][1]) >> (1 << k);
            }
        }
        let inp_copy = *inp;
        vec_mul(inp, &inp_copy, &scalars[j]);
    }
}
fn transpose_64x64(out: &mut [u64; 64], input: &[u64; 64]) {
    const MASKS: [[u64; 2]; 6] = [
        [0x5555_5555_5555_5555, 0xAAAA_AAAA_AAAA_AAAA],
        [0x3333_3333_3333_3333, 0xCCCC_CCCC_CCCC_CCCC],
        [0x0F0F_0F0F_0F0F_0F0F, 0xF0F0_F0F0_F0F0_F0F0],
        [0x00FF_00FF_00FF_00FF, 0xFF00_FF00_FF00_FF00],
        [0x0000_FFFF_0000_FFFF, 0xFFFF_0000_FFFF_0000],
        [0x0000_0000_FFFF_FFFF, 0xFFFF_FFFF_0000_0000],
    ];
    *out = *input;
    for d in (0..=5).rev() {
        let s = 1usize << d;
        let [mask_lo, mask_hi] = MASKS[d];
        for i in (0..64).step_by(s * 2) {
            for j in i..(i + s) {
                let x = (out[j] & mask_lo) | ((out[j + s] & mask_lo) << s);
                let y = ((out[j] & mask_hi) >> s) | (out[j + s] & mask_hi);
                out[j] = x;
                out[j + s] = y;
            }
        }
    }
}
pub(crate) fn butterflies(
    out: &mut [[Vec64; GFBITS]; 64],
    inp: &mut [Vec64; GFBITS],
    consts: &[[u64; 12]; 63],
    powers: &[[u64; 12]; 64],
) {
    let mut tmp = [0u64; GFBITS];
    const REVERSAL: [u8; 64] = [
        0, 32, 16, 48, 8, 40, 24, 56, 4, 36, 20, 52, 12, 44, 28, 60, 2, 34, 18, 50, 10, 42, 26, 58,
        6, 38, 22, 54, 14, 46, 30, 62, 1, 33, 17, 49, 9, 41, 25, 57, 5, 37, 21, 53, 13, 45, 29, 61,
        3, 35, 19, 51, 11, 43, 27, 59, 7, 39, 23, 55, 15, 47, 31, 63,
    ];
    for j in 0..64 {
        for i in 0..GFBITS {
            out[j][i] = (inp[i] >> REVERSAL[j]) & 1;
            out[j][i] = 0u64.wrapping_sub(out[j][i]);
        }
    }
    let mut consts_ptr = 0usize;
    for i in 0..=5 {
        let s = 1 << i;
        for j in (0..64).step_by(2 * s) {
            for k in j..j + s {
                vec_mul(&mut tmp, &out[k + s], &consts[consts_ptr + (k - j)]);
                for b in 0..GFBITS {
                    out[k][b] ^= tmp[b];
                }
                for b in 0..GFBITS {
                    out[k + s][b] ^= out[k][b];
                }
            }
        }
        consts_ptr += s;
    }
    for i in 0..64 {
        for b in 0..GFBITS {
            out[i][b] ^= powers[i][b];
        }
    }
}
pub(crate) fn fft(
    out: &mut [[Vec64; GFBITS]; 64],
    inp: &mut [Vec64; GFBITS],
    consts: &[[u64; 12]; 63],
    powers: &[[u64; 12]; 64],
    scalars: &[[u64; 12]; 5],
) {
    radix_conversions(inp, scalars);
    butterflies(out, inp, consts, powers);
}
fn gf_mul(a: Gf, b: Gf) -> Gf {
    crate::gf::gf_mul::<12>(a, b)
}
fn gf_inv(den: Gf) -> Gf {
    let mut out = den;
    out = gf_sq(out);
    let tmp_11 = gf_mul(out, den);
    out = gf_sq(tmp_11);
    out = gf_sq(out);
    let tmp_1111 = gf_mul(out, tmp_11);
    out = gf_sq(tmp_1111);
    out = gf_sq(out);
    out = gf_sq(out);
    out = gf_sq(out);
    out = gf_mul(out, tmp_1111);
    out = gf_sq(out);
    out = gf_sq(out);
    out = gf_mul(out, tmp_11);
    out = gf_sq(out);
    out = gf_mul(out, den);
    gf_sq(out)
}
fn gf_sq(inp: Gf) -> Gf {
    const B: [u32; 4] = [0x5555_5555, 0x3333_3333, 0x0F0F_0F0F, 0x00FF_00FF];
    let mut x = u32::from(inp);
    x = (x | (x << 8)) & B[3];
    x = (x | (x << 4)) & B[2];
    x = (x | (x << 2)) & B[1];
    x = (x | (x << 1)) & B[0];
    let mut t = x & 0x7FC000;
    x ^= (t >> 9) ^ (t >> 12);
    t = x & 0x003000;
    x ^= (t >> 9) ^ (t >> 12);
    u16::try_from(x & u32::from(GFMASK)).expect("gf_sq result fits in u16")
}
fn gf_iszero(a: Gf) -> Gf {
    let mut t = u32::from(a);
    t = t.wrapping_sub(1);
    t >>= 19;
    u16::try_from(t).expect("gf_iszero result fits in u16")
}
fn gf_mul_poly(out: &mut [Gf; SYS_T], lhs: &[Gf; SYS_T], rhs: &[Gf; SYS_T]) {
    let mut prod = [0u16; SYS_T * 2 - 1];
    for i in 0..SYS_T {
        for j in 0..SYS_T {
            let a = u32::from(lhs[i]);
            let b = u32::from(rhs[j]);
            let mut tmp = a * (b & 1);
            let mut k = 1;
            while k < GFBITS {
                tmp ^= a * (b & (1 << k));
                k += 1;
            }
            let mut t = tmp & 0x7FC000;
            tmp ^= t >> 9;
            tmp ^= t >> 12;
            t = tmp & 0x3000;
            tmp ^= t >> 9;
            tmp ^= t >> 12;
            prod[i + j] ^= (tmp & u32::from(GFMASK)) as u16;
        }
    }
    match SYS_T {
        64 => {
            for i in (SYS_T..=SYS_T * 2 - 2).rev() {
                prod[i - 61] ^= prod[i];
                prod[i - 63] ^= prod[i];
                prod[i - 64] ^= {
                    let carry = (prod[i] >> (GFBITS - 1)) & 1;
                    ((prod[i] << 1) ^ (0u16.wrapping_sub(carry) & 0x9)) & GFMASK
                };
            }
        }
        96 => {
            for i in (SYS_T..=SYS_T * 2 - 2).rev() {
                prod[i - 86] ^= prod[i];
                prod[i - 87] ^= prod[i];
                prod[i - 90] ^= prod[i];
                prod[i - 96] ^= prod[i];
            }
        }
        128 => {
            for i in (SYS_T..=SYS_T * 2 - 2).rev() {
                prod[i - 121] ^= prod[i];
                prod[i - 126] ^= prod[i];
                prod[i - 127] ^= prod[i];
                prod[i - 128] ^= prod[i];
            }
        }
        119 => {
            for i in (SYS_T..=SYS_T * 2 - 2).rev() {
                prod[i - 111] ^= prod[i];
                prod[i - 119] ^= prod[i];
            }
        }
        _ => {
            // SAFETY: SYS_T is monomorphized by the variant parameter; all supported
            unreachable!()
        }
    }
    out.copy_from_slice(&prod[..SYS_T]);
}
pub(crate) fn genpoly_gen(out: &mut [Gf; SYS_T], f: &[Gf; SYS_T]) -> bool {
    let mut mat = [[0u16; SYS_T]; SYS_T + 1];
    mat[0][0] = 1;
    mat[1].copy_from_slice(f);
    for j in 2..=SYS_T {
        let prev = mat[j - 1];
        let mut row = [0u16; SYS_T];
        gf_mul_poly(&mut row, &prev, f);
        mat[j] = row;
    }
    for j in 0..SYS_T {
        for k in (j + 1)..SYS_T {
            let mask = gf_iszero(mat[j][j]) & GFMASK;
            for col in j..=SYS_T {
                mat[col][j] ^= mat[col][k] & mask;
            }
        }
        if gf_iszero(mat[j][j]) != 0 {
            return true;
        }
        let inv = gf_inv(mat[j][j]);
        for col in j..=SYS_T {
            mat[col][j] = gf_mul(mat[col][j], inv);
        }
        for k in 0..SYS_T {
            if k == j {
                continue;
            }
            let t = mat[j][k];
            for col in j..=SYS_T {
                mat[col][k] ^= gf_mul(mat[col][j], t);
            }
        }
    }
    out.copy_from_slice(&mat[SYS_T]);
    false
}
pub(crate) fn irr_load(out: &mut [Vec64; GFBITS], input: &[u8]) {
    let mut irr = [0u16; SYS_T + 1];
    for i in 0..SYS_T {
        irr[i] = load_gf(&input[i * 2..]) & GFMASK;
    }
    irr[SYS_T] = 1;
    for i in 0..GFBITS {
        let mut v = 0u64;
        for j in (0..=SYS_T).rev() {
            v <<= 1;
            v |= u64::from((irr[j] >> i) & 1);
        }
        out[i] = v;
    }
}
fn bitrev(value: Gf) -> Gf {
    let mut x = value;
    x = ((x & 0x00ff) << 8) | ((x & 0xff00) >> 8);
    x = ((x & 0x0f0f) << 4) | ((x & 0xf0f0) >> 4);
    x = ((x & 0x3333) << 2) | ((x & 0xcccc) >> 2);
    x = ((x & 0x5555) << 1) | ((x & 0xaaaa) >> 1);
    x >> 4
}
pub(crate) fn support_gen(support: &mut [Gf; SYS_N], c: &[u8]) {
    let mut l = [[0u64; 64]; GFBITS];
    for i in 0..(1 << GFBITS) {
        let a = bitrev(u16::try_from(i).expect("i < 2^12 fits in u16"));
        for j in 0..GFBITS {
            l[j][i >> 6] |= u64::from((a >> j) & 1) << (i & 63);
        }
    }
    for row in &mut l {
        let mut data = [0u64; 64];
        data.copy_from_slice(row);
        benes(&mut data, c, false);
        row.copy_from_slice(&data);
    }
    for i in 0..SYS_N {
        support[i] = 0;
        for j in (0..GFBITS).rev() {
            support[i] <<= 1;
            support[i] |= ((l[j][i >> 6] >> (i & 63)) & 1) as Gf;
        }
    }
}
fn layer(data: &mut [u64; 64], bits: &[u64], lgs: usize) {
    let s = 1 << lgs;
    let mut bit_idx = 0usize;
    for i in (0..64).step_by(s * 2) {
        for j in i..i + s {
            let d = (data[j] ^ data[j + s]) & bits[bit_idx];
            data[j] ^= d;
            data[j + s] ^= d;
            bit_idx += 1;
        }
    }
}
pub(crate) fn benes(r: &mut [u64; 64], bits: &[u8], rev: bool) {
    let (inc, cond_ptr_start) = if !rev {
        (256i64, 0usize)
    } else {
        (-256i64, (2 * GFBITS - 2) * 256)
    };
    let mut cond_ptr = i64::try_from(cond_ptr_start).expect("cond_ptr_start fits in i64");
    let r_in = *r;
    transpose_64x64(r, &r_in);
    for low in 0..=5 {
        let mut cond = [0u64; 64];
        for i in 0..64 {
            cond[i] = load4(
                &bits[usize::try_from(cond_ptr + i64::try_from(i).expect("i fits in i64") * 4)
                    .expect("offset fits in usize")..],
            );
        }
        let cond_in = cond;
        transpose_64x64(&mut cond, &cond_in);
        layer(r, &cond, low);
        cond_ptr += inc;
    }
    let r_in = *r;
    transpose_64x64(r, &r_in);
    for low in 0..=5 {
        let mut cond = [0u64; 64];
        for i in 0..32 {
            cond[i] = load8(
                &bits[usize::try_from(cond_ptr + i64::try_from(i).expect("i fits in i64") * 8)
                    .expect("offset fits in usize")..],
            );
        }
        layer(r, &cond, low);
        cond_ptr += inc;
    }
    for low in (0..=4).rev() {
        let mut cond = [0u64; 64];
        for i in 0..32 {
            cond[i] = load8(
                &bits[usize::try_from(cond_ptr + i64::try_from(i).expect("i fits in i64") * 8)
                    .expect("offset fits in usize")..],
            );
        }
        layer(r, &cond, low);
        cond_ptr += inc;
    }
    let r_in = *r;
    transpose_64x64(r, &r_in);
    for low in (0..=5).rev() {
        let mut cond = [0u64; 64];
        for i in 0..64 {
            cond[i] = load4(
                &bits[usize::try_from(cond_ptr + i64::try_from(i).expect("i fits in i64") * 4)
                    .expect("offset fits in usize")..],
            );
        }
        let cond_in = cond;
        transpose_64x64(&mut cond, &cond_in);
        layer(r, &cond, low);
        cond_ptr += inc;
    }
    let r_in = *r;
    transpose_64x64(r, &r_in);
}
pub(crate) fn de_bitslicing(out: &mut [u64], inp: &[[Vec64; GFBITS]; 64]) {
    for item in out.iter_mut() {
        *item = 0;
    }
    for i in 0..64 {
        for j in (0..GFBITS).rev() {
            for r in 0..64 {
                out[i * 64 + r] <<= 1;
                out[i * 64 + r] |= (inp[i][j] >> r) & 1;
            }
        }
    }
}
fn to_bitslicing_2x(
    out0: &mut [[Vec64; GFBITS]; 64],
    out1: &mut [[Vec64; GFBITS]; 64],
    inp: &[u64],
) {
    for i in 0..64 {
        for j in 0..GFBITS {
            out0[i][j] = 0;
            out1[i][j] = 0;
        }
        for j in (0..GFBITS).rev() {
            for r in (0..64).rev() {
                out1[i][j] <<= 1;
                out1[i][j] |= (inp[i * 64 + r] >> (j + GFBITS)) & 1;
            }
        }
        for j in (0..GFBITS).rev() {
            for r in (0..64).rev() {
                out0[i][GFBITS - 1 - j] <<= 1;
                out0[i][GFBITS - 1 - j] |= (inp[i * 64 + r] >> j) & 1;
            }
        }
    }
}
pub(crate) fn pk_gen(
    pk: &mut Vec<u8>,
    irr: &[u8],
    perm: &[u32],
    pi_out: &mut [i16],
    consts: &[[u64; 12]; 63],
    powers: &[[u64; 12]; 64],
    scalars: &[[u64; 12]; 5],
) -> Result<(), crate::error::Error> {
    let nblocks_h = (SYS_N).div_ceil(64);
    let nblocks_i = (PK_NROWS).div_ceil(64);
    let tail = PK_NROWS % 64;
    let block_idx = if tail == 0 { nblocks_i } else { nblocks_i - 1 };
    let mut mat = vec![0u64; PK_NROWS * nblocks_h];
    let mut ops = vec![0u64; PK_NROWS * nblocks_i];
    let mut irr_int = [0u64; GFBITS];
    irr_load(&mut irr_int, irr);
    let mut eval = [[0u64; GFBITS]; 64];
    fft(&mut eval, &mut irr_int, consts, powers, scalars);
    let mut prod = [[0u64; GFBITS]; 64];
    vec_copy(&mut prod[0], &eval[0]);
    for i in 1..64 {
        let prev = prod[i - 1];
        vec_mul(&mut prod[i], &prev, &eval[i]);
    }
    let mut tmp = [0u64; GFBITS];
    vec_inv(&mut tmp, &prod[63]);
    for i in (0..=62).rev() {
        let prev = prod[i];
        let tmp_copy = tmp;
        vec_mul(&mut prod[i + 1], &prev, &tmp);
        vec_mul(&mut tmp, &tmp_copy, &eval[i + 1]);
    }
    vec_copy(&mut prod[0], &tmp);
    let mut list = [0u64; 1 << GFBITS];
    de_bitslicing(&mut list, &prod);
    for i in 0..(1 << GFBITS) {
        list[i] <<= GFBITS;
        list[i] |= i as u64;
        list[i] |= u64::from(perm[i]) << 31;
    }
    crate::sort::uint64_sort(&mut list);
    for i in 1..(1 << GFBITS) {
        if (list[i - 1] >> 31) == (list[i] >> 31) {
            return Err(crate::error::Error::KeygenFailed);
        }
    }
    let mut consts = [[0u64; GFBITS]; 64];
    to_bitslicing_2x(&mut consts, &mut prod, &list);
    for i in 0..(1 << GFBITS) {
        pi_out[i] = i16::try_from(list[i] & u64::from(GFMASK)).expect("GFMASK value fits in i16");
    }
    for j in 0..nblocks_i {
        for k in 0..GFBITS {
            mat[k * nblocks_h + j] = prod[j][k];
        }
    }
    for i in 1..SYS_T {
        for j in 0..nblocks_i {
            let prod_j = prod[j];
            vec_mul(&mut prod[j], &prod_j, &consts[j]);
            for k in 0..GFBITS {
                mat[(i * GFBITS + k) * nblocks_h + j] = prod[j][k];
            }
        }
    }
    for i in 0..PK_NROWS {
        ops[i * nblocks_i + (i / 64)] = 1u64 << (i % 64);
    }
    let column = if tail != 0 {
        let mut col = vec![0u64; PK_NROWS];
        for i in 0..PK_NROWS {
            col[i] = mat[i * nblocks_h + block_idx];
        }
        Some(col)
    } else {
        None
    };
    for row in 0..PK_NROWS {
        let i = row >> 6;
        let j = row & 63;
        for k in (row + 1)..PK_NROWS {
            let bit = (mat[row * nblocks_h + i] >> j) & 1;
            let mask = bit.wrapping_sub(1);
            for c in 0..nblocks_i {
                mat[row * nblocks_h + c] ^= mat[k * nblocks_h + c] & mask;
                ops[row * nblocks_i + c] ^= ops[k * nblocks_i + c] & mask;
            }
        }
        let mask = (mat[row * nblocks_h + i] >> j) & 1;
        if mask == 0 {
            return Err(crate::error::Error::KeygenFailed);
        }
        for k in (row + 1)..PK_NROWS {
            let mask2 = (mat[k * nblocks_h + i] >> j) & 1;
            let neg_mask = 0u64.wrapping_sub(mask2);
            for c in 0..nblocks_i {
                mat[k * nblocks_h + c] ^= mat[row * nblocks_h + c] & neg_mask;
                ops[k * nblocks_i + c] ^= ops[row * nblocks_i + c] & neg_mask;
            }
        }
    }
    for row in (0..PK_NROWS).rev() {
        for k in 0..row {
            let mask = 0u64.wrapping_sub((mat[k * nblocks_h + (row / 64)] >> (row % 64)) & 1);
            for c in 0..nblocks_i {
                ops[k * nblocks_i + c] ^= ops[row * nblocks_i + c] & mask;
            }
        }
    }
    for j in nblocks_i..nblocks_h {
        for k in 0..GFBITS {
            mat[k * nblocks_h + j] = prod[j][k];
        }
    }
    for i in 1..SYS_T {
        for j in nblocks_i..nblocks_h {
            let prod_j = prod[j];
            vec_mul(&mut prod[j], &prod_j, &consts[j]);
            for k in 0..GFBITS {
                mat[(i * GFBITS + k) * nblocks_h + j] = prod[j][k];
            }
        }
    }
    if let Some(ref column) = column {
        for i in 0..PK_NROWS {
            mat[i * nblocks_h + block_idx] = column[i];
        }
    }
    pk.clear();
    for row in 0..PK_NROWS {
        let mut one_row = vec![0u64; nblocks_h];
        for c in 0..PK_NROWS {
            let mask = 0u64.wrapping_sub((ops[row * nblocks_i + (c >> 6)] >> (c & 63)) & 1);
            for k in block_idx..nblocks_h {
                one_row[k] ^= mat[c * nblocks_h + k] & mask;
            }
        }
        if tail == 0 {
            for k in block_idx..nblocks_h - 1 {
                pk.extend_from_slice(&one_row[k].to_le_bytes());
            }
            let last = one_row[nblocks_h - 1];
            let rem = PK_ROW_BYTES % 8;
            if rem != 0 {
                let pk_len = pk.len();
                pk.resize(pk_len + rem, 0);
                store_i(&mut pk[pk_len..], last, rem);
            } else {
                pk.extend_from_slice(&last.to_le_bytes());
            }
        } else {
            for k in block_idx..nblocks_h - 1 {
                let shifted = (one_row[k] >> tail) | (one_row[k + 1] << (64 - tail));
                pk.extend_from_slice(&shifted.to_le_bytes());
            }
            let last = one_row[nblocks_h - 1] >> tail;
            let rem = PK_ROW_BYTES % 8;
            if rem != 0 {
                let pk_len = pk.len();
                pk.resize(pk_len + rem, 0);
                store_i(&mut pk[pk_len..], last, rem);
            } else {
                pk.extend_from_slice(&last.to_le_bytes());
            }
        }
    }
    let expected = PK_NROWS * PK_ROW_BYTES;
    pk.truncate(expected);
    Ok(())
}
#[must_use]
pub(crate) fn syndrome_from_public_key(pk: &[u8], e: &[u8]) -> [u8; SYND_BYTES] {
    let mut s = [0u8; SYND_BYTES];
    let pk_rows_bytes = PK_NROWS / 8;
    let pk_rows_rem = PK_NROWS % 8;
    s[..pk_rows_bytes].copy_from_slice(&e[..pk_rows_bytes]);
    if pk_rows_rem != 0 {
        s[pk_rows_bytes] = e[pk_rows_bytes] & ((1 << pk_rows_rem) - 1);
    }
    let bit_offset = PK_NROWS % 8;
    let e_start = PK_NROWS / 8;
    let ncols_words = PK_NCOLS / 64;
    for i in 0..PK_NROWS {
        let row_start = i * PK_ROW_BYTES;
        let mut parity = 0u64;
        if bit_offset == 0 {
            for j in 0..ncols_words {
                let row_word = load8(&pk[row_start + j * 8..]);
                let e_word = load8(&e[e_start + j * 8..]);
                parity ^= u64::from((row_word & e_word).count_ones());
            }
        } else {
            for j in 0..ncols_words {
                let row_word = load8(&pk[row_start + j * 8..]);
                let lo = load8(&e[e_start + j * 8..]);
                let hi = load8(&e[e_start + (j + 1) * 8..]);
                let e_word = (lo >> bit_offset) | (hi << (64 - bit_offset));
                parity ^= u64::from((row_word & e_word).count_ones());
            }
        }
        let rem = PK_NCOLS % 64;
        if rem > 0 {
            let tail_bytes = (rem).div_ceil(8);
            let mut row_tail = 0u64;
            let mut e_tail = 0u64;
            for b in 0..tail_bytes {
                if b * 8 < pk.len() {
                    row_tail |= u64::from(pk[row_start + ncols_words * 8 + b]) << (b * 8);
                }
                let idx = e_start + ncols_words * 8 + b;
                if idx < e.len() {
                    e_tail |= u64::from(e[idx]) << (b * 8);
                }
            }
            if bit_offset != 0 {
                e_tail >>= bit_offset;
                let carry_idx = e_start + ncols_words * 8 + tail_bytes;
                if carry_idx < e.len() {
                    e_tail |= u64::from(e[carry_idx]) << (64 - bit_offset);
                }
            }
            parity ^= u64::from((row_tail & e_tail).count_ones());
        }
        let bit = (parity & 1) as u8;
        s[i / 8] ^= bit << (i % 8);
    }
    s
}
#[must_use]
pub(crate) fn decrypt_error_vector(sk: &[u8], c: &[u8]) -> ([u8; SYS_N / 8], u8) {
    let irr_start = 40usize;
    let cond_start = irr_start + IRR_BYTES;
    let irr_bytes = &sk[irr_start..cond_start];
    let mut g = SecretArray::<u16, { SYS_T + 1 }>::new();
    for i in 0..SYS_T {
        g[i] = load_gf(&irr_bytes[i * 2..]) & GFMASK;
    }
    g[SYS_T] = 1;
    let cond = &sk[cond_start..cond_start + COND_BYTES];
    let mut support = SecretArray::<u16, SYS_N>::new();
    support_gen(&mut support, cond);
    let (e_vec, valid) =
        decode::decrypt_with_support::<GFBITS>(g.as_ref(), support.as_ref(), c, SYS_N, SYS_T);
    let mut e = [0u8; SYS_N / 8];
    e.copy_from_slice(&e_vec);
    (e, valid)
}
fn controlbits_layer(p: &mut [i16], cb: &[u8], s: usize, n: usize) {
    let stride = 1usize << s;
    let mut index = 0usize;
    for i in (0..n).step_by(stride * 2) {
        for j in 0..stride {
            let mut d = p[i + j] ^ p[i + j + stride];
            let mut m = i16::from((cb[index >> 3] >> (index & 7)) & 1);
            m = -m;
            d &= m;
            p[i + j] ^= d;
            p[i + j + stride] ^= d;
            index += 1;
        }
    }
}
fn cbrecursion_write(out: &mut [u8], pos: usize, step: usize, pi: &[i16], w: usize, n: usize) {
    if w == 1 {
        out[pos >> 3] ^= { u8::try_from(pi[0]).expect("pi[0] fits in u8") } << (pos & 7);
        return;
    }
    let mut a = [0i32; 1 << GFBITS];
    let mut b = [0i32; 1 << GFBITS];
    for x in 0..n {
        a[x] = (i32::from(pi[x] ^ 1) << 16)
            | i32::from(u16::try_from(pi[x ^ 1]).expect("pi[x^1] fits in u16"));
    }
    crate::sort::int32_sort(&mut a[..n]);
    for x in 0..n {
        let ax = a[x];
        let px = ax & 0xffff;
        let cx = crate::sort::int32_min(px, i32::try_from(x).expect("x fits in i32"));
        b[x] = (px << 16) | cx;
    }
    for (x, ax) in a[..n].iter_mut().enumerate() {
        *ax = (*ax << 16) | i32::try_from(x).expect("x fits in i32");
    }
    crate::sort::int32_sort(&mut a[..n]);
    for x in 0..n {
        a[x] = (a[x] << 16) | (b[x] >> 16);
    }
    crate::sort::int32_sort(&mut a[..n]);
    if w <= 10 {
        for x in 0..n {
            b[x] = ((a[x] & 0xffff) << 10) | (b[x] & 0x3ff);
        }
        for _ in 1..(w - 1) {
            for (x, ax) in a[..n].iter_mut().enumerate() {
                *ax = ((b[x] & !0x3ff) << 6) | i32::try_from(x).expect("x fits in i32");
            }
            crate::sort::int32_sort(&mut a[..n]);
            for x in 0..n {
                a[x] = (a[x] << 20) | b[x];
            }
            crate::sort::int32_sort(&mut a[..n]);
            for x in 0..n {
                let ppcpx = a[x] & 0xfffff;
                let ppcx = (a[x] & 0xffc00) | (b[x] & 0x3ff);
                b[x] = crate::sort::int32_min(ppcx, ppcpx);
            }
        }
        for x in 0..n {
            b[x] &= 0x3ff;
        }
    } else {
        for x in 0..n {
            b[x] = (a[x] << 16) | (b[x] & 0xffff);
        }
        for i in 1..(w - 1) {
            for (x, ax) in a[..n].iter_mut().enumerate() {
                *ax = (b[x] & !0xffff) | i32::try_from(x).expect("x fits in i32");
            }
            crate::sort::int32_sort(&mut a[..n]);
            for x in 0..n {
                a[x] = (a[x] << 16) | (b[x] & 0xffff);
            }
            if i < w - 2 {
                for x in 0..n {
                    b[x] = (a[x] & !0xffff) | ((b[x] >> 16) & 0xffff);
                }
                crate::sort::int32_sort(&mut b[..n]);
                for x in 0..n {
                    b[x] = (b[x] << 16) | (a[x] & 0xffff);
                }
            }
            crate::sort::int32_sort(&mut a[..n]);
            for x in 0..n {
                let cpx = (b[x] & !0xffff) | (a[x] & 0xffff);
                b[x] = crate::sort::int32_min(b[x], cpx);
            }
        }
        for x in 0..n {
            b[x] &= 0xffff;
        }
    }
    let mut p = pos;
    for j in 0..(n / 2) {
        let x = 2 * j;
        let fj = u8::try_from(b[x] & 1).expect("bit fits in u8");
        out[p >> 3] ^= fj << (p & 7);
        p += step;
    }
    for x in 0..n {
        a[x] = (i32::from(pi[x]) << 16) + i32::try_from(x).expect("x fits in i32");
    }
    crate::sort::int32_sort(&mut a[..n]);
    for j in 0..(n / 2) {
        let x = 2 * j;
        let fj = b[x] & 1;
        let fx = i32::try_from(x).expect("x fits in i32") + fj;
        let fx1 = fx ^ 1;
        b[x] = (a[x] << 16) | fx;
        b[x + 1] = (a[x + 1] << 16) | fx1;
    }
    crate::sort::int32_sort(&mut b[..n]);
    p += (2 * w - 3) * step * (n / 2);
    for k in 0..(n / 2) {
        let y = 2 * k;
        let lk = u8::try_from(b[y] & 1).expect("bit fits in u8");
        out[p >> 3] ^= lk << (p & 7);
        p += step;
        let ly = i32::try_from(y).expect("fits in i32") + i32::from(lk);
        let ly1 = ly ^ 1;
        a[y] = (ly << 16) | (b[y] & 0xffff);
        a[y + 1] = (ly1 << 16) | (b[y + 1] & 0xffff);
    }
    crate::sort::int32_sort(&mut a[..n]);
    let mut q = [0i16; 1 << GFBITS];
    for j in 0..(n / 2) {
        q[j] = ((a[2 * j] & 0xffff) >> 1) as i16;
        q[j + n / 2] = ((a[2 * j + 1] & 0xffff) >> 1) as i16;
    }
    let recurse_pos = pos + step * n / 2;
    cbrecursion_write(out, recurse_pos, step * 2, &q[..n / 2], w - 1, n / 2);
    cbrecursion_write(out, recurse_pos + step, step * 2, &q[n / 2..], w - 1, n / 2);
}
pub(crate) fn controlbits_from_permutation(
    out: &mut [u8],
    pi: &[i16],
) -> Result<(), crate::error::Error> {
    let n = 1 << GFBITS;
    for _ in 0..128 {
        for b in out.iter_mut() {
            *b = 0;
        }
        cbrecursion_write(out, 0, 1, pi, GFBITS, n);
        let mut pi_test = [0i16; 1 << GFBITS];
        for (i, slot) in pi_test.iter_mut().enumerate() {
            *slot = i16::try_from(i).expect("i fits in i16");
        }
        let mut ptr = 0usize;
        for i in 0..GFBITS {
            controlbits_layer(&mut pi_test, &out[ptr..], i, n);
            ptr += n >> 4;
        }
        for i in (0..=(GFBITS - 2)).rev() {
            controlbits_layer(&mut pi_test, &out[ptr..], i, n);
            ptr += n >> 4;
        }
        let mut diff = 0i16;
        for i in 0..n {
            diff |= pi[i] ^ pi_test[i];
        }
        if diff == 0 {
            return Ok(());
        }
    }
    Err(crate::error::Error::KeygenFailed)
}
