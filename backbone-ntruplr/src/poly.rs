//! Polynomial arithmetic in Rq and R3 for Streamlined NTRU Prime.
//!
//! Rq = Z/qZ[x]/((x^p - x - 1))
//! R3 = GF(3)[x]/((x^p - x - 1))
//!
//! Both `P` (ring dimension) and `Q` (modulus) are const generic parameters
//! so that variants with different parameters reuse the same code.
//!
//! Ring reduction: x^p = x + 1

use alloc::vec;
use backbone_pqcrypto_internals::karatsuba::{karatsuba_mul, reduce_ring};
use backbone_pqcrypto_internals::secret::{SecretArray, SecretVec};
use core::fmt;

/// Fixed-point multiply used by the reference rounded encoder.
const ROUND_MULT: i32 = 10923;

/// R3 encoding bytes: 2 bits per coefficient, rounded up to byte.
pub(crate) const fn r3_encoded_bytes(p: usize) -> usize {
    (p * 2).div_ceil(8)
}

/// Rounded Rq encoding bytes for binary-tree Encode with modulus (q+2)/3.
pub(crate) const fn rq_rounded_bytes(p: usize, q: i16) -> usize {
    tree_encoded_bytes(p, (u16::from_ne_bytes(q.to_ne_bytes()) as u64).div_ceil(3))
}

const fn tree_encoded_bytes(p: usize, m_val: u64) -> usize {
    if p == 0 {
        return 0;
    }
    const LIMIT: u64 = 16384;
    const MAX_P: usize = 900;

    let mut mods = [0u64; MAX_P];
    let mut i = 0;
    while i < p {
        mods[i] = m_val;
        i += 1;
    }
    let mut len = p;
    let mut total = 0usize;

    while len > 1 {
        let mut j = 0;
        let mut write_idx = 0;
        while j + 1 < len {
            let mut m = mods[j] * mods[j + 1];
            while m >= LIMIT {
                total += 1;
                m = m.div_ceil(256);
            }
            mods[write_idx] = m;
            write_idx += 1;
            j += 2;
        }
        if j < len {
            mods[write_idx] = mods[j];
            write_idx += 1;
        }
        len = write_idx;
    }

    let mut m = mods[0];
    while m > 1 {
        total += 1;
        m = m.div_ceil(256);
    }
    total
}

/// `QSHIFT = Q / 2` (floor) — shift to make coefficients non-negative.
pub(crate) fn qshift(q: i16) -> i32 {
    i32::from(q / 2)
}

/// First Barrett multiplier: floor(2^20 / Q) — matches reference.
pub(crate) fn barrett_m1(q: i16) -> i32 {
    let q_u64 = u64::try_from(q).expect("Q is positive");
    i32::try_from((1u64 << 20) / q_u64).expect("Barrett m1 fits in i32")
}

/// Second Barrett multiplier: floor(2^28 / Q) — matches reference.
pub(crate) fn barrett_m2(q: i16) -> i32 {
    let q_u64 = u64::try_from(q).expect("Q is positive");
    i32::try_from((1u64 << 28) / q_u64).expect("Barrett m2 fits in i32")
}

/// Fast modular reduction to signed range.
fn modq_freeze<const Q: i16>(a: i32) -> i16 {
    let q = i32::from(Q);
    let m1 = barrett_m1(Q);
    let m2 = barrett_m2(Q);
    let mut a = a;
    a -= q * ((m1 * a) >> 20);
    a -= q * ((m2 * a + 134217728) >> 28);
    i16::try_from(a).expect("Barrett-reduced value fits in i16")
}

pub(crate) fn mod3_freeze(a: i32) -> i8 {
    let mut a = a;
    a -= 3 * ((10923 * a) >> 15);
    a -= 3 * ((89478485 * a + 134217728) >> 28);
    i8::try_from(a).expect("mod3_freeze: value reduced to {-1,0,1}")
}
/// A polynomial in Rq = Z/qZ[x]/((x^p - x - 1)).
/// Coefficients are stored as `i16` in signed range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rq<const P: usize, const Q: i16>(pub SecretArray<i16, P>);

impl<const P: usize, const Q: i16> Default for Rq<P, Q> {
    fn default() -> Self {
        Rq(SecretArray::new())
    }
}

impl<const P: usize, const Q: i16> fmt::Display for Rq<P, Q> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rq({} coeffs)", P)
    }
}

impl<const P: usize, const Q: i16> Rq<P, Q> {
    pub(crate) fn encode_rounded(&self, out: &mut [u8]) -> Result<(), &'static str> {
        let rounded_bytes = rq_rounded_bytes(P, Q);
        if out.len() < rounded_bytes {
            return Err("Rq::encode_rounded: buffer too small");
        }
        let qs = qshift(Q);
        let m_val = u64::from(u16::from_ne_bytes(Q.to_ne_bytes())).div_ceil(3);
        let values: vec::Vec<u64> = (0..P)
            .map(|i| {
                u64::try_from(((i32::from(self.0[i]) + qs) * ROUND_MULT) >> 15)
                    .expect("rounded value is non-negative")
            })
            .collect();
        let enc =
            backbone_pqcrypto_internals::tree_encode::rounded_encode(values, alloc::vec![m_val; P]);
        out[..rounded_bytes].copy_from_slice(&enc[..rounded_bytes]);
        Ok(())
    }

    pub(crate) fn decode_rounded(input: &[u8]) -> Result<Self, &'static str> {
        let rounded_bytes = rq_rounded_bytes(P, Q);
        if input.len() < rounded_bytes {
            return Err("Rq::decode_rounded: buffer too small");
        }
        let qs = qshift(Q);
        let q = i32::from(Q);
        let m_val = u64::from(u16::from_ne_bytes(Q.to_ne_bytes())).div_ceil(3);
        let mut r = Rq(SecretArray::new());
        let values = backbone_pqcrypto_internals::tree_encode::rounded_decode(
            &input[..rounded_bytes],
            m_val,
            P,
        )
        .ok_or("Rq::decode_rounded: truncated input")?;
        if values.len() != P {
            return Err("Rq::decode_rounded: malformed input");
        }
        for i in 0..P {
            r.0[i] = modq_freeze::<Q>(
                i32::try_from(values[i] * 3).expect("decoded value fits in i32") + q - qs,
            );
        }
        Ok(r)
    }

    /// Reference Round: subtract coefficient modulo 3.
    pub(crate) fn round3(&self) -> Self {
        let mut r = Rq(SecretArray::new());
        for i in 0..P {
            let x = i32::from(self.0[i]);
            r.0[i] = i16::try_from(x - i32::from(mod3_freeze(x)))
                .expect("rounded coefficient fits in i16");
        }
        r
    }

    /// Multiply by a small polynomial (R3 → Rq lift) via Karatsuba.
    pub(crate) fn mul_small(&self, other: &R3<P>) -> Self
    where
        [i8; P]: Sized,
    {
        let mut a_i64 = [0i64; P];
        let mut b_i64 = [0i64; P];
        for (i, (&a_val, &b_val)) in self.0.iter().zip(other.0.iter()).enumerate() {
            a_i64[i] = i64::from(a_val);
            b_i64[i] = i64::from(b_val);
        }
        let mut acc = SecretVec::<i64>::new(2 * P);
        karatsuba_mul(&mut acc, &a_i64, &b_i64, P);
        reduce_ring(&mut acc, P);
        let mut r = Rq(SecretArray::new());
        for (i, &v) in acc[..P].iter().enumerate() {
            r.0[i] = modq_freeze::<Q>(i32::try_from(v % i64::from(Q)).expect("v%Q fits in i32"));
        }
        r
    }
}

/// A polynomial in R3 = GF(3)[x]/((x^p - x - 1)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct R3<const P: usize>(pub SecretArray<i8, P>);

impl<const P: usize> Default for R3<P> {
    fn default() -> Self {
        R3(SecretArray::new())
    }
}

impl<const P: usize> fmt::Display for R3<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "R3({} coeffs)", P)
    }
}

impl<const P: usize> R3<P> {
    pub(crate) fn encode(&self, out: &mut [u8]) -> Result<(), &'static str> {
        let enc = r3_encoded_bytes(P);
        if out.len() < enc {
            return Err("R3::encode: buffer too small");
        }
        out.fill(0);
        for i in 0..P {
            let byte_idx = i / 4;
            let bit_off = 2 * (i % 4);
            let val: u8 = match self.0[i] {
                -1 => 0b00,
                0 => 0b01,
                1 => 0b10,
                _ => 0b01,
            };
            out[byte_idx] |= val << bit_off;
        }
        Ok(())
    }

    pub(crate) fn decode(input: &[u8]) -> Result<Self, &'static str> {
        let enc = r3_encoded_bytes(P);
        if input.len() < enc {
            return Err("R3::decode: buffer too small");
        }
        let mut r = R3(SecretArray::new());
        for i in 0..P {
            let byte_idx = i / 4;
            let bit_off = 2 * (i % 4);
            let bits = (input[byte_idx] >> bit_off) & 3;
            r.0[i] = match bits {
                0b00 => -1,
                0b01 => 0,
                0b10 => 1,
                _ => -1,
            };
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_rq_round3_encode_decode() {
        const P: usize = 761;
        const Q: i16 = 4591;
        let qs = qshift(Q);
        let mut poly = Rq::<P, Q>(SecretArray::new());
        for i in 0..P {
            poly.0[i] = ((i as i32 * 54321) % i32::from(Q) - qs) as i16;
        }
        let rounded = poly.round3();
        let mut buf = vec![0u8; rq_rounded_bytes(P, Q)];
        rounded.encode_rounded(&mut buf).unwrap();
        let decoded = Rq::<P, Q>::decode_rounded(&buf).unwrap();
        assert_eq!(rounded, decoded);
    }

    #[test]
    fn test_r3_encode_decode() {
        const P: usize = 761;
        let mut poly = R3::<P>(SecretArray::new());
        for i in 0..P {
            poly.0[i] = match i % 3 {
                0 => 0,
                1 => 1,
                _ => -1,
            };
        }
        let mut buf = vec![0u8; r3_encoded_bytes(P)];
        poly.encode(&mut buf).unwrap();
        let decoded = R3::<P>::decode(&buf).unwrap();
        assert_eq!(poly, decoded);
    }

    #[test]
    fn test_modq_freeze_range() {
        const Q: i16 = 4591;
        for val in [-5000i32, -4591, -2295, 0, 2295, 4590, 5000] {
            let frozen = modq_freeze::<Q>(val);
            let frozen_i32 = i32::from(frozen);
            assert!(
                frozen_i32 >= -(i32::from(Q) / 2) && frozen_i32 <= i32::from(Q) / 2,
                "modq_freeze({}) = {} out of range",
                val,
                frozen
            );
        }
    }
}
