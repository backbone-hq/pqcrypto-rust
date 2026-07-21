use crate::field::csubq;
use crate::params::*;
use alloc::vec;
use alloc::vec::Vec;
use pqcrypto_utils::secret::SecretArray;

pub(crate) struct Poly {
    pub coeffs: SecretArray<i16, N>,
}

impl Poly {
    pub(crate) fn new() -> Self {
        Poly {
            coeffs: SecretArray::new(),
        }
    }

    pub(crate) fn from_coeffs(coeffs: [i16; N]) -> Self {
        Poly {
            coeffs: SecretArray::from_array(coeffs),
        }
    }

    pub(crate) fn compress(&self, d: usize) -> Poly {
        let mut r = Poly::new();
        for i in 0..N {
            let x = i32::from(self.coeffs[i]);
            let x = x + ((x >> 31) & Q);
            let val = ((x << d) + (Q >> 1)) / Q;
            r.coeffs[i] =
                i16::try_from(val & ((1 << d) - 1)).expect("val masked by (1<<d)-1 fits in i16");
        }
        r
    }

    pub(crate) fn decompress(&self, d: usize) -> Poly {
        let mut r = Poly::new();
        for i in 0..N {
            let y = i32::from(self.coeffs[i]);
            let val = (y * Q + (1 << (d - 1))) >> d;
            r.coeffs[i] = csubq(if val >= Q {
                i16::try_from(Q - 1).expect("Q-1 fits in i16")
            } else {
                i16::try_from(val).expect("val < Q fits in i16")
            });
        }
        r
    }

    /// ByteEncode_12: pack 256 12-bit coefficients into 384 bytes
    pub(crate) fn encode_12(&self) -> [u8; 384] {
        let mut out = [0u8; 384];
        for i in 0..128 {
            let t0 = u16::try_from(i32::from(self.coeffs[2 * i]).rem_euclid(Q))
                .expect("rem_euclid(Q) fits in u16");
            let t1 = u16::try_from(i32::from(self.coeffs[2 * i + 1]).rem_euclid(Q))
                .expect("rem_euclid(Q) fits in u16");
            out[3 * i] = u8::try_from(t0 & 0xFF).expect("low byte fits in u8");
            out[3 * i + 1] =
                u8::try_from((t0 >> 8) | ((t1 & 0x00F) << 4)).expect("value fits in u8");
            out[3 * i + 2] = u8::try_from(t1 >> 4).expect("value fits in u8");
        }
        out
    }

    /// ByteDecode_12: unpack 384 bytes into 256 12-bit coefficients
    pub(crate) fn decode_12(bytes: &[u8]) -> Self {
        let mut coeffs = [0i16; N];
        for i in 0..128 {
            let b0 = u16::from(bytes[3 * i]);
            let b1 = u16::from(bytes[3 * i + 1]);
            let b2 = u16::from(bytes[3 * i + 2]);
            let c0 = i16::try_from(b0 | ((b1 & 0x0F) << 8)).expect("12-bit coeff fits in i16");
            let c1 = i16::try_from((b1 >> 4) | (b2 << 4)).expect("12-bit coeff fits in i16");
            coeffs[2 * i] = c0;
            coeffs[2 * i + 1] = c1;
        }
        Poly {
            coeffs: SecretArray::from_array(coeffs),
        }
    }

    /// ByteEncode_d: pack 256 d-bit coefficients into ceil(256*d/8) bytes
    pub(crate) fn byte_encode(&self, d: usize) -> Vec<u8> {
        let total_bits = N * d;
        let total_bytes = total_bits.div_ceil(8);
        let mut out = vec![0u8; total_bytes];
        for i in 0..N {
            let val = (u16::from_ne_bytes(self.coeffs[i].to_ne_bytes())) & ((1 << d) - 1);
            let bit_pos = i * d;
            let byte_idx = bit_pos / 8;
            let bit_off = bit_pos % 8;
            let b0 = u8::try_from((val << bit_off) & 0xff).expect("low byte fits in u8");
            out[byte_idx] |= b0;
            if bit_off + d > 8 {
                let b1 = u8::try_from((val >> (8 - bit_off)) & 0xff).expect("low byte fits in u8");
                out[byte_idx + 1] |= b1;
            }
            if bit_off + d > 16 {
                let b2 = u8::try_from((val >> (16 - bit_off)) & 0xff).expect("low byte fits in u8");
                out[byte_idx + 2] |= b2;
            }
        }
        out
    }

    /// ByteDecode_d: unpack bytes into 256 d-bit coefficients
    pub(crate) fn byte_decode(bytes: &[u8], d: usize) -> Self {
        let mut coeffs = [0i16; N];
        let mask = (1 << d) - 1;
        for i in 0..N {
            let bit_pos = i * d;
            let byte_idx = bit_pos / 8;
            let bit_off = bit_pos % 8;
            let v = u32::from(bytes[byte_idx])
                | if bit_off + d > 8 {
                    u32::from(bytes[byte_idx + 1]) << 8
                } else {
                    0
                }
                | if bit_off + d > 16 {
                    u32::from(bytes[byte_idx + 2]) << 16
                } else {
                    0
                };
            coeffs[i] = i16::try_from((v >> bit_off) & mask).expect("masked value fits in i16");
        }
        Poly {
            coeffs: SecretArray::from_array(coeffs),
        }
    }

    /// Decode 32-byte message into polynomial with coefficients 0 or (Q+1)/2.
    pub(crate) fn from_msg(msg: &[u8]) -> Self {
        let mut coeffs = [0i16; N];
        let q_half = i16::try_from((Q + 1) / 2).expect("Q half fits in i16");
        for i in 0..32 {
            for j in 0..8 {
                let bit = (msg[i] >> j) & 1;
                coeffs[8 * i + j] = 0i16.wrapping_sub(i16::from(bit)) & q_half;
            }
        }
        Poly {
            coeffs: SecretArray::from_array(coeffs),
        }
    }
}

pub(crate) struct PolyVec<const K: usize> {
    pub vec: [Poly; K],
}

impl<const K: usize> PolyVec<K> {
    pub(crate) fn new() -> Self {
        PolyVec {
            vec: [0; K].map(|_| Poly::new()),
        }
    }

    pub(crate) fn from_arrays(arr: &[[i16; N]; K]) -> Self {
        let mut r = PolyVec::new();
        for i in 0..K {
            r.vec[i] = Poly::from_coeffs(arr[i]);
        }
        r
    }

    pub(crate) fn encode_12(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(K * 384);
        for i in 0..K {
            out.extend_from_slice(&self.vec[i].encode_12());
        }
        out
    }

    pub(crate) fn decode_12(bytes: &[u8]) -> Self {
        let mut r = PolyVec::new();
        for i in 0..K {
            let off = i * 384;
            r.vec[i] = Poly::decode_12(&bytes[off..off + 384]);
        }
        r
    }

    pub(crate) fn byte_encode(&self, d: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for i in 0..K {
            out.extend_from_slice(&self.vec[i].byte_encode(d));
        }
        out
    }

    pub(crate) fn byte_decode(bytes: &[u8], d: usize) -> Self {
        let mut r = PolyVec::new();
        let per_poly = (N * d).div_ceil(8);
        for i in 0..K {
            let off = i * per_poly;
            r.vec[i] = Poly::byte_decode(&bytes[off..off + per_poly], d);
        }
        r
    }

    pub(crate) fn compress(&self, d: usize) -> PolyVec<K> {
        let mut r = PolyVec::new();
        for i in 0..K {
            r.vec[i] = self.vec[i].compress(d);
        }
        r
    }

    pub(crate) fn decompress(&self, d: usize) -> PolyVec<K> {
        let mut r = PolyVec::new();
        for i in 0..K {
            r.vec[i] = self.vec[i].decompress(d);
        }
        r
    }
}
