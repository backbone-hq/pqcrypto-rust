// GFBITS=13 variant for mceliece460896
use crate::common::*;
use crate::decode;
use crate::vec_ops::gf13::*;
use alloc::vec;
use alloc::vec::Vec;
use backbone_pqcrypto_internals::secret::SecretArray;
pub(crate) const GFBITS: usize = 13;
pub(crate) const SYS_T: usize = 96;
pub(crate) const SYS_N: usize = 4608;
pub(crate) const PK_NROWS: usize = 1248;
pub(crate) const PK_NCOLS: usize = 3360;
pub(crate) const PK_ROW_BYTES: usize = 420;
pub(crate) const SYND_BYTES: usize = 156;
pub(crate) const IRR_BYTES: usize = 192;
pub(crate) const COND_BYTES: usize = 12800;
pub(crate) const GFMASK: u16 = 8191u16;
pub(crate) const CRYPTO_PUBLICKEYBYTES: usize = 524160;
pub(crate) const CRYPTO_SECRETKEYBYTES: usize = 13608;
pub(crate) const CRYPTO_CIPHERTEXTBYTES: usize = 156;
pub(crate) const CRYPTO_BYTES: usize = 32;

/// No-op post-process step for the forward FFT (GFBITS=13 variant).
fn fft_postprocess(_out: &mut [[Vec64; GFBITS]; 128], _powers: &[[u64; 13]; 128]) {}

// ── Shake256 helper ─────────────────────────────────────────────────────────

/// Hash `input` with SHAKE-256, writing the result into `output`.
pub(crate) fn shake256_into(output: &mut [u8], input: &[u8]) {
    let mut x = sha3::Shake256::default();
    x.update(input);
    x.finalize_xof().read(output);
}

// ── Load / store helpers ────────────────────────────────────────────────────

/// Load up to 8 bytes from `b` into a `u64` (little-endian).
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

/// Load a `Gf` value from 2 bytes (little-endian).
pub(crate) fn load_gf(b: &[u8]) -> Gf {
    u16::from(b[0]) | (u16::from(b[1]) << 8)
}

/// Store a `Gf` value as 2 bytes (little-endian).
pub(crate) fn store_gf(b: &mut [u8], v: Gf) {
    b[0] = u8::try_from(v & 0xff).expect("gf low byte fits in u8");
    b[1] = u8::try_from((v >> 8) & 0xff).expect("gf high byte fits in u8");
}

/// Load a `u32` from 4 bytes (little-endian).
pub(crate) fn load4(b: &[u8]) -> u32 {
    u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16) | (u32::from(b[3]) << 24)
}

/// Store `i` bytes of `v` (little-endian) into `out`.
fn store_i(out: &mut [u8], v: u64, i: usize) {
    for j in 0..i {
        out[j] = u8::try_from((v >> (j * 8)) & 0xff).expect("byte fits in u8");
    }
}

// ── Gao-Mateer FFT (128-point, 2-way vectors) ────────────────────────

/// Radix-conversion step of the forward Gao-Mateer FFT.
fn radix_conversions(inp: &mut [[Vec64; GFBITS]; 2], scalars_2x: &[[[u64; 13]; 2]; 5]) {
    const MASKS: [[u64; 2]; 5] = [
        [0x8888_8888_8888_8888, 0x4444_4444_4444_4444],
        [0xC0C0_C0C0_C0C0_C0C0, 0x3030_3030_3030_3030],
        [0xF000_F000_F000_F000, 0x0F00_0F00_0F00_0F00],
        [0xFF00_0000_FF00_0000, 0x00FF_0000_00FF_0000],
        [0xFFFF_0000_0000_0000, 0x0000_FFFF_0000_0000],
    ];
    for j in 0..=5 {
        for i in 0..GFBITS {
            inp[1][i] ^= inp[1][i] >> 32;
            inp[0][i] ^= inp[1][i] << 32;
        }
        for i in 0..GFBITS {
            for k in (j..=4).rev() {
                inp[0][i] ^= (inp[0][i] & MASKS[k][0]) >> (1 << k);
                inp[0][i] ^= (inp[0][i] & MASKS[k][1]) >> (1 << k);
                inp[1][i] ^= (inp[1][i] & MASKS[k][0]) >> (1 << k);
                inp[1][i] ^= (inp[1][i] & MASKS[k][1]) >> (1 << k);
            }
        }
        if j < 5 {
            let row0 = inp[0];
            let row1 = inp[1];
            vec_mul(&mut inp[0], &row0, &scalars_2x[j][0]);
            vec_mul(&mut inp[1], &row1, &scalars_2x[j][1]);
        }
    }
}

/// In-place 64×64 bit-matrix transposition.
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

/// Butterfly layers of the forward Gao-Mateer FFT.
fn butterflies(
    out: &mut [[Vec64; GFBITS]; 128],
    inp: &mut [[Vec64; GFBITS]; 2],
    consts: &[[u64; 13]; 128],
) {
    let mut tmp = [0u64; GFBITS];
    let mut pre = [[0u64; GFBITS]; 8];
    const REVERSAL: [u8; 128] = [
        0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120, 4, 68, 36, 100, 20, 84,
        52, 116, 12, 76, 44, 108, 28, 92, 60, 124, 2, 66, 34, 98, 18, 82, 50, 114, 10, 74, 42, 106,
        26, 90, 58, 122, 6, 70, 38, 102, 22, 86, 54, 118, 14, 78, 46, 110, 30, 94, 62, 126, 1, 65,
        33, 97, 17, 81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121, 5, 69, 37, 101, 21, 85, 53, 117,
        13, 77, 45, 109, 29, 93, 61, 125, 3, 67, 35, 99, 19, 83, 51, 115, 11, 75, 43, 107, 27, 91,
        59, 123, 7, 71, 39, 103, 23, 87, 55, 119, 15, 79, 47, 111, 31, 95, 63, 127,
    ];
    const BETA: [u16; 7] = [2522, 7827, 7801, 8035, 6897, 8167, 3476];
    for i in 0..7 {
        for j in 0..GFBITS {
            pre[i][j] = vec_setbits(u64::from((BETA[i] >> j) & 1));
        }
        let pre_i = pre[i];
        vec_mul(&mut pre[i], &inp[1], &pre_i);
    }
    for i in 0..GFBITS {
        let mut buf = [0u64; 128];
        buf[0] = inp[0][i];
        buf[1] = buf[0] ^ pre[0][i];
        buf[32] = inp[0][i] ^ pre[5][i];
        buf[3] = buf[1] ^ pre[1][i];
        buf[96] = buf[32] ^ pre[6][i];
        buf[97] = buf[96] ^ pre[0][i];
        buf[2] = inp[0][i] ^ pre[1][i];
        buf[99] = buf[97] ^ pre[1][i];
        buf[6] = buf[2] ^ pre[2][i];
        buf[98] = buf[99] ^ pre[0][i];
        buf[7] = buf[6] ^ pre[0][i];
        buf[102] = buf[98] ^ pre[2][i];
        buf[5] = buf[7] ^ pre[1][i];
        buf[103] = buf[102] ^ pre[0][i];
        buf[101] = buf[103] ^ pre[1][i];
        buf[4] = inp[0][i] ^ pre[2][i];
        buf[100] = buf[101] ^ pre[0][i];
        buf[12] = buf[4] ^ pre[3][i];
        buf[108] = buf[100] ^ pre[3][i];
        buf[13] = buf[12] ^ pre[0][i];
        buf[109] = buf[108] ^ pre[0][i];
        buf[15] = buf[13] ^ pre[1][i];
        buf[111] = buf[109] ^ pre[1][i];
        buf[14] = buf[15] ^ pre[0][i];
        buf[110] = buf[111] ^ pre[0][i];
        buf[10] = buf[14] ^ pre[2][i];
        buf[106] = buf[110] ^ pre[2][i];
        buf[11] = buf[10] ^ pre[0][i];
        buf[107] = buf[106] ^ pre[0][i];
        buf[9] = buf[11] ^ pre[1][i];
        buf[105] = buf[107] ^ pre[1][i];
        buf[104] = buf[105] ^ pre[0][i];
        buf[8] = inp[0][i] ^ pre[3][i];
        buf[120] = buf[104] ^ pre[4][i];
        buf[24] = buf[8] ^ pre[4][i];
        buf[121] = buf[120] ^ pre[0][i];
        buf[25] = buf[24] ^ pre[0][i];
        buf[123] = buf[121] ^ pre[1][i];
        buf[27] = buf[25] ^ pre[1][i];
        buf[122] = buf[123] ^ pre[0][i];
        buf[26] = buf[27] ^ pre[0][i];
        buf[126] = buf[122] ^ pre[2][i];
        buf[30] = buf[26] ^ pre[2][i];
        buf[127] = buf[126] ^ pre[0][i];
        buf[31] = buf[30] ^ pre[0][i];
        buf[125] = buf[127] ^ pre[1][i];
        buf[29] = buf[31] ^ pre[1][i];
        buf[124] = buf[125] ^ pre[0][i];
        buf[28] = buf[29] ^ pre[0][i];
        buf[116] = buf[124] ^ pre[3][i];
        buf[20] = buf[28] ^ pre[3][i];
        buf[117] = buf[116] ^ pre[0][i];
        buf[21] = buf[20] ^ pre[0][i];
        buf[119] = buf[117] ^ pre[1][i];
        buf[23] = buf[21] ^ pre[1][i];
        buf[118] = buf[119] ^ pre[0][i];
        buf[22] = buf[23] ^ pre[0][i];
        buf[114] = buf[118] ^ pre[2][i];
        buf[18] = buf[22] ^ pre[2][i];
        buf[115] = buf[114] ^ pre[0][i];
        buf[19] = buf[18] ^ pre[0][i];
        buf[113] = buf[115] ^ pre[1][i];
        buf[17] = buf[19] ^ pre[1][i];
        buf[112] = buf[113] ^ pre[0][i];
        buf[80] = buf[112] ^ pre[5][i];
        buf[16] = inp[0][i] ^ pre[4][i];
        buf[81] = buf[80] ^ pre[0][i];
        buf[48] = buf[16] ^ pre[5][i];
        buf[83] = buf[81] ^ pre[1][i];
        buf[49] = buf[48] ^ pre[0][i];
        buf[82] = buf[83] ^ pre[0][i];
        buf[51] = buf[49] ^ pre[1][i];
        buf[86] = buf[82] ^ pre[2][i];
        buf[50] = buf[51] ^ pre[0][i];
        buf[87] = buf[86] ^ pre[0][i];
        buf[54] = buf[50] ^ pre[2][i];
        buf[85] = buf[87] ^ pre[1][i];
        buf[55] = buf[54] ^ pre[0][i];
        buf[84] = buf[85] ^ pre[0][i];
        buf[53] = buf[55] ^ pre[1][i];
        buf[92] = buf[84] ^ pre[3][i];
        buf[52] = buf[53] ^ pre[0][i];
        buf[93] = buf[92] ^ pre[0][i];
        buf[60] = buf[52] ^ pre[3][i];
        buf[95] = buf[93] ^ pre[1][i];
        buf[61] = buf[60] ^ pre[0][i];
        buf[94] = buf[95] ^ pre[0][i];
        buf[63] = buf[61] ^ pre[1][i];
        buf[90] = buf[94] ^ pre[2][i];
        buf[62] = buf[63] ^ pre[0][i];
        buf[91] = buf[90] ^ pre[0][i];
        buf[58] = buf[62] ^ pre[2][i];
        buf[89] = buf[91] ^ pre[1][i];
        buf[59] = buf[58] ^ pre[0][i];
        buf[88] = buf[89] ^ pre[0][i];
        buf[57] = buf[59] ^ pre[1][i];
        buf[72] = buf[88] ^ pre[4][i];
        buf[56] = buf[57] ^ pre[0][i];
        buf[73] = buf[72] ^ pre[0][i];
        buf[40] = buf[56] ^ pre[4][i];
        buf[75] = buf[73] ^ pre[1][i];
        buf[41] = buf[40] ^ pre[0][i];
        buf[74] = buf[75] ^ pre[0][i];
        buf[43] = buf[41] ^ pre[1][i];
        buf[78] = buf[74] ^ pre[2][i];
        buf[42] = buf[43] ^ pre[0][i];
        buf[79] = buf[78] ^ pre[0][i];
        buf[46] = buf[42] ^ pre[2][i];
        buf[77] = buf[79] ^ pre[1][i];
        buf[47] = buf[46] ^ pre[0][i];
        buf[76] = buf[77] ^ pre[0][i];
        buf[45] = buf[47] ^ pre[1][i];
        buf[68] = buf[76] ^ pre[3][i];
        buf[44] = buf[45] ^ pre[0][i];
        buf[69] = buf[68] ^ pre[0][i];
        buf[36] = buf[44] ^ pre[3][i];
        buf[71] = buf[69] ^ pre[1][i];
        buf[37] = buf[36] ^ pre[0][i];
        buf[70] = buf[71] ^ pre[0][i];
        buf[39] = buf[37] ^ pre[1][i];
        buf[66] = buf[70] ^ pre[2][i];
        buf[38] = buf[39] ^ pre[0][i];
        buf[67] = buf[66] ^ pre[0][i];
        buf[34] = buf[38] ^ pre[2][i];
        buf[65] = buf[67] ^ pre[1][i];
        buf[35] = buf[34] ^ pre[0][i];
        buf[33] = buf[35] ^ pre[1][i];
        buf[64] = inp[0][i] ^ pre[6][i];
        let mut lo: [u64; 64] = [0; 64];
        lo.copy_from_slice(&buf[..64]);
        let lo_in = lo;
        let mut hi: [u64; 64] = [0; 64];
        hi.copy_from_slice(&buf[64..128]);
        let hi_in = hi;
        transpose_64x64(&mut lo, &lo_in);
        transpose_64x64(&mut hi, &hi_in);
        buf[..64].copy_from_slice(&lo);
        buf[64..128].copy_from_slice(&hi);
        for j in 0..128 {
            out[REVERSAL[j] as usize][i] = buf[j];
        }
    }
    let mut consts_ptr = 2usize;
    for i in 1..=6 {
        let s = 1 << i;
        for j in (0..128).step_by(2 * s) {
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
}

/// Copy a bitsliced vector `[Vec64; GFBITS]` from `inp` to `out`.
fn vec_copy(out: &mut [Vec64; GFBITS], inp: &[Vec64; GFBITS]) {
    out.copy_from_slice(inp);
}

/// Forward Gao-Mateer FFT (128-point, GFBITS=13).
pub(crate) fn fft(
    out: &mut [[Vec64; GFBITS]; 128],
    inp: &mut [[Vec64; GFBITS]; 2],
    consts: &[[u64; 13]; 128],
    scalars_2x: &[[[u64; 13]; 2]; 5],
    powers: &[[u64; 13]; 128],
) {
    radix_conversions(inp, scalars_2x);
    butterflies(out, inp, consts);
    fft_postprocess(out, powers);
}

// ── Benes network (128-element, for GFBITS=13) ───────────────────────

/// Benes network inner layer (horizontal-style bit manipulation).
fn layer_in(data: &mut [u64; 128], bits: &[u64], lgs: usize) {
    let s = 1 << lgs;
    let mut bit = 0;
    for i in (0..64).step_by(s * 2) {
        for j in i..i + s {
            let d0 = (data[j] ^ data[j + s]) & bits[bit];
            data[j] ^= d0;
            data[j + s] ^= d0;
            bit += 1;
            let d1 = (data[j + 64] ^ data[j + s + 64]) & bits[bit];
            data[j + 64] ^= d1;
            data[j + s + 64] ^= d1;
            bit += 1;
        }
    }
}

/// Benes network outer layer.
fn layer_ex(data: &mut [u64; 128], bits: &[u64], lgs: usize) {
    let s = 1 << lgs;
    let mut bit = 0;
    for i in (0..128).step_by(s * 2) {
        for j in i..i + s {
            let d = (data[j] ^ data[j + s]) & bits[bit];
            data[j] ^= d;
            data[j + s] ^= d;
            bit += 1;
        }
    }
}

/// Benes network routing for 128-element vectors.
pub(crate) fn benes(r: &mut [u64; 128], bits: &[u8], rev: bool) {
    let mut r_int_v = [0u64; 128];
    let mut r_int_h = [0u64; 128];
    let mut b_int_v = [0u64; 64];
    let mut b_int_h = [0u64; 64];
    for i in 0..64 {
        r_int_v[i] = r[i * 2];
        r_int_v[i + 64] = r[i * 2 + 1];
    }
    let mut bits_ptr: usize = if rev { 12288 } else { 0 };
    let inc: isize = if rev { -1024 } else { 0 };
    let (rv0, rv1) = r_int_v.split_at_mut(64);
    let (rh0, rh1) = r_int_h.split_at_mut(64);
    transpose_64x64(
        (&mut rh0[..64])
            .try_into()
            .expect("rh0 has exactly 64 elements"),
        (&rv0[..64])
            .try_into()
            .expect("rv0 has exactly 64 elements"),
    );
    transpose_64x64(
        (&mut rh1[..64])
            .try_into()
            .expect("rh1 has exactly 64 elements"),
        (&rv1[..64])
            .try_into()
            .expect("rv1 has exactly 64 elements"),
    );
    for _iter in 0..=6 {
        for i in 0..64 {
            b_int_v[i] = load8(&bits[bits_ptr..]);
            bits_ptr = bits_ptr.wrapping_add(8);
        }
        bits_ptr = bits_ptr.wrapping_add_signed(inc);
        let bv = b_int_v;
        transpose_64x64(&mut b_int_h, &bv);
        layer_ex(&mut r_int_h, &b_int_h, _iter);
    }
    let (rh0, rh1) = r_int_h.split_at_mut(64);
    let (rv0, rv1) = r_int_v.split_at_mut(64);
    transpose_64x64(
        (&mut rv0[..64])
            .try_into()
            .expect("rv0 has exactly 64 elements"),
        (&rh0[..64])
            .try_into()
            .expect("rh0 has exactly 64 elements"),
    );
    transpose_64x64(
        (&mut rv1[..64])
            .try_into()
            .expect("rv1 has exactly 64 elements"),
        (&rh1[..64])
            .try_into()
            .expect("rh1 has exactly 64 elements"),
    );
    for _iter in 0..=5 {
        for i in 0..64 {
            b_int_v[i] = load8(&bits[bits_ptr..]);
            bits_ptr = bits_ptr.wrapping_add(8);
        }
        bits_ptr = bits_ptr.wrapping_add_signed(inc);
        layer_in(&mut r_int_v, &b_int_v, _iter);
    }
    for _iter in (0..=4).rev() {
        for i in 0..64 {
            b_int_v[i] = load8(&bits[bits_ptr..]);
            bits_ptr = bits_ptr.wrapping_add(8);
        }
        bits_ptr = bits_ptr.wrapping_add_signed(inc);
        layer_in(&mut r_int_v, &b_int_v, _iter);
    }
    let (rh0, rh1) = r_int_h.split_at_mut(64);
    let (rv0, rv1) = r_int_v.split_at_mut(64);
    transpose_64x64(
        (&mut rh0[..64])
            .try_into()
            .expect("rh0 has exactly 64 elements"),
        (&rv0[..64])
            .try_into()
            .expect("rv0 has exactly 64 elements"),
    );
    transpose_64x64(
        (&mut rh1[..64])
            .try_into()
            .expect("rh1 has exactly 64 elements"),
        (&rv1[..64])
            .try_into()
            .expect("rv1 has exactly 64 elements"),
    );
    for _iter in (0..=6).rev() {
        for i in 0..64 {
            b_int_v[i] = load8(&bits[bits_ptr..]);
            bits_ptr = bits_ptr.wrapping_add(8);
        }
        bits_ptr = bits_ptr.wrapping_add_signed(inc);
        let bv = b_int_v;
        transpose_64x64(&mut b_int_h, &bv);
        layer_ex(&mut r_int_h, &b_int_h, _iter);
    }
    let (rh0, rh1) = r_int_h.split_at_mut(64);
    let (rv0, rv1) = r_int_v.split_at_mut(64);
    transpose_64x64(
        (&mut rv0[..64])
            .try_into()
            .expect("rv0 has exactly 64 elements"),
        (&rh0[..64])
            .try_into()
            .expect("rh0 has exactly 64 elements"),
    );
    transpose_64x64(
        (&mut rv1[..64])
            .try_into()
            .expect("rv1 has exactly 64 elements"),
        (&rh1[..64])
            .try_into()
            .expect("rh1 has exactly 64 elements"),
    );
    for i in 0..64 {
        r[i * 2] = r_int_v[i];
        r[i * 2 + 1] = r_int_v[i + 64];
    }
}

// ── irr_load (bitsliced, 2-vector for GFBITS=13) ─────────────────────

/// Load an irreducible Goppa polynomial from bytes into bitsliced 2-vector form.
fn irr_load(out: &mut [[Vec64; GFBITS]; 2], input: &[u8]) {
    let mut irr = [0u16; SYS_T + 1];
    for i in 0..SYS_T {
        irr[i] = load_gf(&input[i * 2..]) & GFMASK;
    }
    irr[SYS_T] = 1;
    for i in 0..GFBITS {
        let mut v0 = 0u64;
        let mut v1 = 0u64;
        for j in (0..=63).rev() {
            v0 <<= 1;
            v0 |= u64::from((irr[j] >> i) & 1);
        }
        for j in (64..=SYS_T).rev() {
            v1 <<= 1;
            v1 |= u64::from((irr[j] >> i) & 1);
        }
        out[0][i] = v0;
        out[1][i] = v1;
    }
}

// ── Support generation (bitsliced for GFBITS=13) ─────────────────────

/// Generate the field-element support from Benes control bits.
pub(crate) fn support_gen(support: &mut [Gf], c: &[u8]) {
    let sys_n = support.len();
    let mut l_full = [[0u64; 128]; GFBITS];
    for i in 0..(1 << GFBITS) {
        let a = bitrev(u16::try_from(i).expect("i < 2^13 fits in u16"));
        for j in 0..GFBITS {
            l_full[j][i >> 6] |= u64::from((a >> j) & 1) << (i & 63);
        }
    }
    for row in &mut l_full {
        let mut data = [0u64; 128];
        data.copy_from_slice(row);
        benes(&mut data, c, false);
        row.copy_from_slice(&data);
    }
    for i in 0..sys_n {
        support[i] = 0;
        for j in (0..GFBITS).rev() {
            support[i] <<= 1;
            support[i] |= ((l_full[j][i >> 6] >> (i & 63)) & 1) as Gf;
        }
    }
}

/// Bit-reverse a 13-bit value (used in support generation).
fn bitrev(value: Gf) -> Gf {
    let mut x = value;
    x = ((x & 0x00ff) << 8) | ((x & 0xff00) >> 8);
    x = ((x & 0x0f0f) << 4) | ((x & 0xf0f0) >> 4);
    x = ((x & 0x3333) << 2) | ((x & 0xcccc) >> 2);
    x = ((x & 0x5555) << 1) | ((x & 0xaaaa) >> 1);
    x >> 3
}

// ── Scalar GF operations (for genpoly_gen) ───────────────────────────

/// Multiply two field elements (GF(2^13) with Goppa polynomial).
fn gf_mul(a: Gf, b: Gf) -> Gf {
    crate::gf::gf_mul::<13>(a, b)
}

/// Invert a field element in GF(2^13).
fn gf_inv(den: Gf) -> Gf {
    let tmp_11 = gf_sqmul(den, den);
    let tmp_1111 = gf_sq2mul(tmp_11, tmp_11);
    let mut out = gf_sq2(tmp_1111);
    out = gf_sq2mul(out, tmp_1111);
    out = gf_sq2(out);
    out = gf_sq2mul(out, tmp_1111);
    gf_sq(out)
}

/// Square a field element in GF(2^13).
fn gf_sq(inp: Gf) -> Gf {
    const B: [u32; 4] = [0x5555_5555, 0x3333_3333, 0x0F0F_0F0F, 0x00FF_00FF];
    let mut x = u32::from(inp);
    x = (x | (x << 8)) & B[3];
    x = (x | (x << 4)) & B[2];
    x = (x | (x << 2)) & B[1];
    x = (x | (x << 1)) & B[0];
    let mut t = x & 0xFF80000;
    x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    t = x & 0x007E000;
    x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    u16::try_from(x & u32::from(GFMASK)).expect("masked gf square fits in u16")
}

/// Double-width square (maps GF(2^13) → GF(2^13)).
fn gf_sq2(inp: Gf) -> Gf {
    const B: [u64; 4] = [
        0x1111_1111_1111_1111,
        0x0303_0303_0303_0303,
        0x000F_000F_000F_000F,
        0x0000_00FF_0000_00FF,
    ];
    const M: [u64; 4] = [
        0x0001_FF00_0000_0000,
        0x0000_00FF_8000_0000,
        0x0000_0000_7FC0_0000,
        0x0000_0000_003F_E000,
    ];
    let mut x = u64::from(inp);
    x = (x | (x << 24)) & B[3];
    x = (x | (x << 12)) & B[2];
    x = (x | (x << 6)) & B[1];
    x = (x | (x << 3)) & B[0];
    for i in 0..4 {
        let t = x & M[i];
        x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    }
    u16::try_from(x & u64::from(GFMASK)).expect("masked gf_sq2 fits in u16")
}

/// Square then multiply: `gf_mul(gf_sq(inp), m)`.
fn gf_sqmul(inp: Gf, m: Gf) -> Gf {
    gf_mul(gf_sq(inp), m)
}

/// Double-square then multiply: `gf_mul(gf_sq2(inp), m)`.
fn gf_sq2mul(inp: Gf, m: Gf) -> Gf {
    gf_mul(gf_sq2(inp), m)
}

/// Test whether a field element is zero (returns GFMASK if zero, 0 otherwise).
fn gf_iszero(a: Gf) -> Gf {
    let mut t = u32::from(a);
    t = t.wrapping_sub(1);
    t >>= 19;
    u16::try_from(t).expect("shift leaves 0 or GFMASK, fits in u16")
}

// ── genpoly_gen (scalar) ─────────────────────────────────────────────

/// Multiply two polynomials of degree `SYS_T-1` over GF(2^13),
/// reducing modulo the Goppa polynomial.
fn gf_mul_poly(out: &mut [Gf; SYS_T], lhs: &[Gf; SYS_T], rhs: &[Gf; SYS_T]) {
    let mut prod = [0u16; SYS_T * 2 - 1];
    for i in 0..SYS_T {
        for j in 0..SYS_T {
            prod[i + j] ^= gf_mul(lhs[i], rhs[j]);
        }
    }
    match SYS_T {
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
            // values (64, 96, 119, 128) are handled above.
            unreachable!()
        }
    }
    out.copy_from_slice(&prod[..SYS_T]);
}

/// Generate the Goppa polynomial generator matrix.
///
/// Returns `true` if the polynomial is not invertible (singular matrix).
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

// ── Public key generation (GFBITS=13 version) ─────────────────────────

/// De-bitslice a 128-element array of `[Vec64; GFBITS]` back into plain `u64`.
fn de_bitslicing(out: &mut [u64], inp: &[[Vec64; GFBITS]; 128]) {
    for item in out.iter_mut() {
        *item = 0;
    }
    for i in 0..128 {
        for j in (0..GFBITS).rev() {
            for r in 0..64 {
                out[i * 64 + r] <<= 1;
                out[i * 64 + r] |= (inp[i][j] >> r) & 1;
            }
        }
    }
}

/// Convert a plain `u64` list into two bitsliced 128-element arrays.
fn to_bitslicing_2x(
    out0: &mut [[Vec64; GFBITS]; 128],
    out1: &mut [[Vec64; GFBITS]; 128],
    inp: &[u64],
) {
    for i in 0..128 {
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

/// Generate the public key from a seed and permutation.
pub(crate) fn pk_gen(
    pk: &mut Vec<u8>,
    irr: &[u8],
    perm: &[u32],
    pi_out: &mut [i16],
    consts: &[[u64; 13]; 128],
    scalars_2x: &[[[u64; 13]; 2]; 5],
    _scalars_4x: &[[[u64; 13]; 4]; 6],
    powers: &[[u64; 13]; 128],
) -> Result<(), crate::error::Error> {
    let nblocks_h = (SYS_N).div_ceil(64);
    let nblocks_i = (PK_NROWS).div_ceil(64);
    let tail = PK_NROWS % 64;
    let block_idx = if tail == 0 { nblocks_i } else { nblocks_i - 1 };
    let mut mat = vec![0u64; PK_NROWS * nblocks_h];
    let mut ops = vec![0u64; PK_NROWS * nblocks_i];
    let mut irr_int = [[0u64; GFBITS]; 2];
    irr_load(&mut irr_int, irr);
    let mut eval = [[0u64; GFBITS]; 128];
    fft(&mut eval, &mut irr_int, consts, scalars_2x, powers);
    let mut prod = [[0u64; GFBITS]; 128];
    vec_copy(&mut prod[0], &eval[0]);
    for i in 1..128 {
        let prev = prod[i - 1];
        vec_mul(&mut prod[i], &prev, &eval[i]);
    }
    let mut tmp = [0u64; GFBITS];
    vec_inv(&mut tmp, &prod[127]);
    for i in (0..=126).rev() {
        let prev = prod[i];
        let tmp_copy = tmp;
        vec_mul(&mut prod[i + 1], &prev, &tmp);
        vec_mul(&mut tmp, &tmp_copy, &eval[i + 1]);
    }
    vec_copy(&mut prod[0], &tmp);
    // de-bitslicing
    let mut list = [0u64; 1 << GFBITS];
    de_bitslicing(&mut list, &prod);
    for i in 0..(1 << GFBITS) {
        list[i] <<= GFBITS;
        list[i] |= i as u64;
        list[i] |= u64::from(perm[i]) << 31;
    }
    // sort
    crate::sort::uint64_sort(&mut list);
    for i in 1..(1 << GFBITS) {
        if (list[i - 1] >> 31) == (list[i] >> 31) {
            return Err(crate::error::Error::KeygenFailed);
        }
    }
    let mut consts = [[0u64; GFBITS]; 128];
    to_bitslicing_2x(&mut consts, &mut prod, &list);
    for i in 0..(1 << GFBITS) {
        pi_out[i] = i16::try_from(list[i] & u64::from(GFMASK)).expect("masked value fits in i16");
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
    // Initialize ops as identity
    for i in 0..PK_NROWS {
        ops[i * nblocks_i + (i / 64)] = 1u64 << (i % 64);
    }
    // column tracking (only needed when non-systematic data shares a word with systematic)
    let column = if tail != 0 {
        let mut col = vec![0u64; PK_NROWS];
        for i in 0..PK_NROWS {
            col[i] = mat[i * nblocks_h + block_idx];
        }
        Some(col)
    } else {
        None
    };
    // Gaussian elimination
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
    // Back-substitution
    for row in (0..PK_NROWS).rev() {
        for k in 0..row {
            let mask = 0u64.wrapping_sub((mat[k * nblocks_h + (row / 64)] >> (row % 64)) & 1);
            for c in 0..nblocks_i {
                ops[k * nblocks_i + c] ^= ops[row * nblocks_i + c] & mask;
            }
        }
    }
    // Apply linear map to non-systematic part
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
    // Restore column (non-systematic data in mixed word)
    if let Some(ref column) = column {
        for i in 0..PK_NROWS {
            mat[i * nblocks_h + block_idx] = column[i];
        }
    }
    // Compute the public key rows
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
    // Truncate to exact public key size
    let expected = PK_NROWS * PK_ROW_BYTES;
    pk.truncate(expected);
    Ok(())
}

// ── Syndrome computation (for encrypt/decaps) ────────────────────────

/// Compute the syndrome from the public key and error vector.
#[must_use]
pub(crate) fn syndrome_from_public_key(pk: &[u8], e: &[u8]) -> [u8; SYND_BYTES] {
    let mut s = [0u8; SYND_BYTES];
    // Identity contribution: s = bitwise e[0..PK_NROWS]
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

// ── Decrypt error vector ─────────────────────────────────────────────

/// Decrypt the error vector from a ciphertext using the secret key.
///
/// Returns the error vector (as bytes) and a validity flag.
#[must_use]
pub(crate) fn decrypt_error_vector(sk: &[u8], c: &[u8]) -> ([u8; SYS_N / 8], u8) {
    let irr_start = 40usize;
    let cond_start = irr_start + IRR_BYTES;
    let irr_bytes = &sk[irr_start..cond_start];
    // Read Goppa polynomial from SK
    let mut g = SecretArray::<u16, { SYS_T + 1 }>::new();
    for i in 0..SYS_T {
        g[i] = load_gf(&irr_bytes[i * 2..]) & GFMASK;
    }
    g[SYS_T] = 1;
    // Reconstruct support from Benes control bits
    let cond = &sk[cond_start..cond_start + COND_BYTES];
    let mut support = SecretArray::<u16, SYS_N>::new();
    support_gen(support.as_mut(), cond);
    // Run the clean-implementation decoder (synd -> bm -> root -> verify)
    let (e_vec, valid) =
        decode::decrypt_with_support::<GFBITS>(g.as_ref(), support.as_ref(), c, SYS_N, SYS_T);
    let mut e = [0u8; SYS_N / 8];
    e.copy_from_slice(&e_vec);
    (e, valid)
}

// ── Sort helpers (used by pk_gen) ──────────────────────────────────────
// ── Control bits (shared with GFBITS=12) ───────────────────────────────

/// Apply one layer of control bits to the partial permutation `p`.
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
        out[pos >> 3] ^= u8::try_from(pi[0] & 1).expect("lsb of i16 fits in u8") << (pos & 7);
        return;
    }
    let mut a = [0i32; 1 << GFBITS];
    let mut b = [0i32; 1 << GFBITS];
    for x in 0..n {
        a[x] = (i32::from(pi[x] ^ 1) << 16)
            | i32::from(u16::try_from(pi[x ^ 1]).expect("non-negative i16 fits in u16"));
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
        let fj = u8::try_from(b[x] & 1).expect("0 or 1 fits in u8");
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
        let lk = u8::try_from(b[y] & 1).expect("0 or 1 fits in u8");
        out[p >> 3] ^= lk << (p & 7);
        p += step;
        let ly = i32::try_from(y).expect("y fits in i32") + i32::from(lk);
        let ly1 = ly ^ 1;
        a[y] = (ly << 16) | (b[y] & 0xffff);
        a[y + 1] = (ly1 << 16) | (b[y + 1] & 0xffff);
    }
    crate::sort::int32_sort(&mut a[..n]);
    let mut q = [0i16; 1 << GFBITS];
    for j in 0..(n / 2) {
        q[j] = i16::try_from((a[2 * j] & 0xffff) >> 1).expect("fits in i16");
        q[j + n / 2] = i16::try_from((a[2 * j + 1] & 0xffff) >> 1).expect("fits in i16");
    }
    let recurse_pos = pos + step * n / 2;
    cbrecursion_write(out, recurse_pos, step * 2, &q[..n / 2], w - 1, n / 2);
    cbrecursion_write(out, recurse_pos + step, step * 2, &q[n / 2..], w - 1, n / 2);
}

/// Generate the Benes control bits for a permutation.
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
            *slot = i16::try_from(i).expect("i < 2^13 fits in i16");
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
