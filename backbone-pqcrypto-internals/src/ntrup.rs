//! NTRU Prime ring arithmetic shared by the `sntrup` and `ntruplr` crates.
//!
//! Rq = Z/qZ[x]/(x^p - x - 1), R3 = GF(3)[x]/(x^p - x - 1), with ring
//! reduction x^p = x + 1. Centralizes the polynomial arithmetic both
//! crates use. All secret-derived buffers use zeroizing wrappers;
//! arithmetic is constant-time.

use crate::ct::ct_count_nonzero;
use crate::karatsuba::{karatsuba_mul, reduce_ring};
use crate::secret::{SecretArray, SecretVec};
use crate::tree_encode;
use alloc::vec;
use core::fmt;

/// Fixed-point multiply used by the reference rounded encoder.
const ROUND_MULT: i32 = 10923;

/// Public-key Rq encoding bytes for binary-tree Encode with modulus q.
#[must_use]
pub const fn rq_encoded_bytes(p: usize, q: i16) -> usize {
    tree_encoded_bytes(p, u16::from_ne_bytes(q.to_ne_bytes()) as u64)
}

/// R3 encoding bytes: 2 bits per coefficient, rounded up to byte.
#[must_use]
pub const fn r3_encoded_bytes(p: usize) -> usize {
    (p * 2).div_ceil(8)
}

/// Rounded-packing bytes for the binary-tree Encode (non-round1 NTRU Prime).
///
/// Computed by simulating the actual tree encoding on a fixed modulus array;
/// this exactly tracks the modulus evolution through each tree level.
#[must_use]
pub const fn rq_rounded_bytes(p: usize, q: i16) -> usize {
    tree_encoded_bytes(p, (u16::from_ne_bytes(q.to_ne_bytes()) as u64).div_ceil(3))
}

/// Simulate the reference binary-tree Encode to count output bytes for a
/// fixed initial modulus.
const fn tree_encoded_bytes(p: usize, m_val: u64) -> usize {
    if p == 0 {
        return 0;
    }
    const LIMIT: u64 = 16384;
    const MAX_P: usize = 2048;

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

    let mut m = if len > 0 { mods[0] } else { m_val };
    while m > 1 {
        total += 1;
        m = m.div_ceil(256);
    }
    total
}

/// `QSHIFT = Q / 2` (floor) — shift to make coefficients non-negative.
#[must_use]
pub const fn qshift(q: i16) -> i32 {
    (q / 2) as i32
}

/// First Barrett multiplier: floor(2^20 / Q) — matches reference.
#[must_use]
pub const fn barrett_m1(q: i16) -> i32 {
    let q_u32 = u16::from_ne_bytes(q.to_ne_bytes()) as u32;
    i32::from_ne_bytes(((1u32 << 20) / q_u32).to_ne_bytes())
}

/// Second Barrett multiplier: floor(2^28 / Q) — matches reference.
#[must_use]
pub const fn barrett_m2(q: i16) -> i32 {
    let q_u32 = u16::from_ne_bytes(q.to_ne_bytes()) as u32;
    i32::from_ne_bytes(((1u32 << 28) / q_u32).to_ne_bytes())
}

/// Fast modular reduction to signed range.
#[must_use]
pub fn modq_freeze<const Q: i16>(a: i32) -> i16 {
    let q = i32::from(Q);
    let m1 = barrett_m1(Q);
    let m2 = barrett_m2(Q);
    let mut a = a;
    a -= q * ((m1 * a) >> 20);
    a -= q * ((m2 * a + 134217728) >> 28);
    i16::try_from(a).expect("modq_freeze: result fits in i16")
}

/// Reduce an integer to {-1, 0, 1} modulo 3, branchlessly.
#[must_use]
pub fn mod3_freeze(a: i32) -> i8 {
    let mut a = a;
    a -= 3 * ((10923 * a) >> 15);
    a -= 3 * ((89478485 * a + 134217728) >> 28);
    i8::try_from(a).expect("mod3_freeze: value reduced to {-1,0,1}")
}

/// Normalize an arbitrary trit to {-1, 0, 1}.
///
/// Used by [`R3::constant`] for constructing test polynomials.
#[must_use]
pub fn mod3_normalize(a: i8) -> i8 {
    let r = a % 3;
    let n = if r < 0 { r + 3 } else { r };
    if n == 2 {
        -1
    } else {
        n
    }
}

/// A polynomial in Rq = Z/qZ`[x]`/(x^p - x - 1).
///
/// Coefficients are stored as `i16` in signed range, in a zeroizing
/// [`SecretArray`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rq<const P: usize, const Q: i16>(pub SecretArray<i16, P>);

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
    /// Encode with the reference binary-tree Encode using modulus q
    /// (full public-key encoding).
    pub fn encode(&self, out: &mut [u8]) -> Result<(), &'static str> {
        let encoded_bytes = rq_encoded_bytes(P, Q);
        if out.len() < encoded_bytes {
            return Err("Rq::encode: buffer too small");
        }
        let qs = qshift(Q);
        let q = u64::from(u16::from_ne_bytes(Q.to_ne_bytes()));
        let mut values = SecretVec::<u64>::new(P);
        for i in 0..P {
            values[i] = u64::try_from(i32::from(self.0[i]) + qs)
                .expect("Rq coefficient shifted into non-negative range");
        }
        let enc = tree_encode::rounded_encode(values, vec![q; P]);
        out[..encoded_bytes].copy_from_slice(&enc[..encoded_bytes]);
        Ok(())
    }

    /// Decode a full public-key encoding produced by [`Rq::encode`].
    pub fn decode(input: &[u8]) -> Result<Self, &'static str> {
        let encoded_bytes = rq_encoded_bytes(P, Q);
        if input.len() < encoded_bytes {
            return Err("Rq::decode: buffer too small");
        }
        let qs = qshift(Q);
        let q = u64::from(u16::from_ne_bytes(Q.to_ne_bytes()));
        let mut r = Rq(SecretArray::new());
        let values = tree_encode::rounded_decode(&input[..encoded_bytes], q, P)
            .ok_or("Rq::decode: truncated input")?;
        if values.len() != P {
            return Err("Rq::decode: malformed input");
        }
        for i in 0..P {
            r.0[i] =
                modq_freeze::<Q>(i32::try_from(values[i]).expect("decoded value fits in i32") - qs);
        }
        Ok(r)
    }

    /// Encode with the rounded binary-tree Encode using modulus (q+2)/3.
    pub fn encode_rounded(&self, out: &mut [u8]) -> Result<(), &'static str> {
        let rounded_bytes = rq_rounded_bytes(P, Q);
        if out.len() < rounded_bytes {
            return Err("Rq::encode_rounded: buffer too small");
        }
        let qs = qshift(Q);
        let m_val = u64::from(u16::from_ne_bytes(Q.to_ne_bytes())).div_ceil(3);

        let mut values = SecretVec::<u64>::new(P);
        for i in 0..P {
            values[i] = u64::try_from(((i32::from(self.0[i]) + qs) * ROUND_MULT) >> 15)
                .expect("non-negative value fits in u64");
        }

        let enc = tree_encode::rounded_encode(values, vec![m_val; P]);
        out[..rounded_bytes].copy_from_slice(&enc[..rounded_bytes]);
        Ok(())
    }

    /// Decode a rounded encoding produced by [`Rq::encode_rounded`].
    pub fn decode_rounded(input: &[u8]) -> Result<Self, &'static str> {
        let rounded_bytes = rq_rounded_bytes(P, Q);
        if input.len() < rounded_bytes {
            return Err("Rq::decode_rounded: buffer too small");
        }
        let qs = qshift(Q);
        let q = i32::from(Q);
        let m_val = u64::from(u16::from_ne_bytes(Q.to_ne_bytes())).div_ceil(3);

        let values = tree_encode::rounded_decode(&input[..rounded_bytes], m_val, P)
            .ok_or("Rq::decode_rounded: truncated input")?;

        if values.len() != P {
            return Err("Rq::decode_rounded: malformed input");
        }

        let mut r = Rq(SecretArray::new());
        for i in 0..P {
            r.0[i] = modq_freeze::<Q>(
                i32::try_from(values[i]).expect("decoded value fits in i32") * 3 + q - qs,
            );
        }
        Ok(r)
    }

    /// Reference Round: subtract each coefficient modulo 3.
    #[must_use]
    pub fn round3(&self) -> Self {
        let mut r = Rq(SecretArray::new());
        for i in 0..P {
            let x = i32::from(self.0[i]);
            r.0[i] = i16::try_from(x - i32::from(mod3_freeze(x)))
                .expect("rounded coefficient fits in i16");
        }
        r
    }

    /// Multiplication in Rq via Karatsuba.
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        let mut a_i64 = SecretArray::<i64, P>::new();
        let mut b_i64 = SecretArray::<i64, P>::new();
        for (i, (&a_val, &b_val)) in self.0.iter().zip(other.0.iter()).enumerate() {
            a_i64[i] = i64::from(a_val);
            b_i64[i] = i64::from(b_val);
        }
        let mut acc = SecretVec::<i64>::new(2 * P);
        karatsuba_mul(&mut acc, a_i64.as_ref(), b_i64.as_ref(), P);
        reduce_ring(&mut acc, P);
        let mut r = Rq(SecretArray::new());
        for (i, &v) in acc[..P].iter().enumerate() {
            r.0[i] = modq_freeze::<Q>(i32::try_from(v % i64::from(Q)).expect("v%Q fits in i32"));
        }
        r
    }

    /// Multiply by a small polynomial (R3 → Rq lift) via Karatsuba.
    ///
    /// All intermediate buffers are zeroizing [`SecretArray`]/[`SecretVec`]:
    /// the R3 coefficients are secret-derived (private key polynomials,
    /// decapsulation values), so the widened i64 copies must not linger.
    #[must_use]
    pub fn mul_small(&self, other: &R3<P>) -> Self
    where
        [i8; P]: Sized,
    {
        let mut a_i64 = SecretArray::<i64, P>::new();
        let mut b_i64 = SecretArray::<i64, P>::new();
        for (i, (&a_val, &b_val)) in self.0.iter().zip(other.0.iter()).enumerate() {
            a_i64[i] = i64::from(a_val);
            b_i64[i] = i64::from(b_val);
        }
        let mut acc = SecretVec::<i64>::new(2 * P);
        karatsuba_mul(&mut acc, a_i64.as_ref(), b_i64.as_ref(), P);
        reduce_ring(&mut acc, P);
        let mut r = Rq(SecretArray::new());
        for (i, &v) in acc[..P].iter().enumerate() {
            r.0[i] = modq_freeze::<Q>(i32::try_from(v % i64::from(Q)).expect("v%Q fits in i32"));
        }
        r
    }
}

/// A polynomial in R3 = GF(3)`[x]`/(x^p - x - 1).
///
/// Coefficients are stored as `i8` in {-1, 0, 1}, in a zeroizing
/// [`SecretArray`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R3<const P: usize>(pub SecretArray<i8, P>);

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
    /// Construct a constant polynomial with a normalized trit at index 0.
    ///
    /// Primarily a test fixture (a monomial); the constant is *not* derived
    /// from secret data.
    #[must_use]
    pub fn constant(v: i8) -> Self {
        let mut r = R3(SecretArray::new());
        r.0[0] = mod3_normalize(v);
        r
    }

    /// Multiplication in R3 via Karatsuba.
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        let mut a_i64 = SecretArray::<i64, P>::new();
        let mut b_i64 = SecretArray::<i64, P>::new();
        for (i, (&a_val, &b_val)) in self.0.iter().zip(other.0.iter()).enumerate() {
            a_i64[i] = i64::from(a_val);
            b_i64[i] = i64::from(b_val);
        }
        let mut acc = SecretVec::<i64>::new(2 * P);
        karatsuba_mul(&mut acc, a_i64.as_ref(), b_i64.as_ref(), P);
        reduce_ring(&mut acc, P);
        let mut r = R3(SecretArray::new());
        for (i, &v) in acc[..P].iter().enumerate() {
            r.0[i] = mod3_freeze((v % 3) as i32);
        }
        r
    }

    /// Constant-time weight: count nonzero coefficients without branching.
    #[must_use]
    pub fn ct_weight(&self) -> usize {
        ct_count_nonzero(self.0.as_ref(), &0i8)
    }

    /// Encode with 2 bits per coefficient, little-endian within each byte.
    ///
    /// Constant-time trit encode: -1 -> 0b00, 0 -> 0b01, 1 -> 0b10.
    /// Branchless arithmetic — a previous 4-way `match` compiled to a jump
    /// table indexed by the secret coefficients being serialized.
    #[allow(clippy::cast_sign_loss)] // intentional 2-bit packing; value masked to {0,1,2} after the cast
    pub fn encode(&self, out: &mut [u8]) -> Result<(), &'static str> {
        let enc = r3_encoded_bytes(P);
        if out.len() < enc {
            return Err("R3::encode: buffer too small");
        }
        out.fill(0);
        for i in 0..P {
            let byte_idx = i / 4;
            let bit_off = 2 * (i % 4);
            let val: u8 = (self.0[i].wrapping_add(1) as u8) & 3;
            out[byte_idx] |= val << bit_off;
        }
        Ok(())
    }

    /// Decode a 2-bits-per-coefficient encoding produced by [`R3::encode`].
    ///
    /// Constant-time trit decode: 00 -> -1, 01 -> 0, 10 -> 1, 11 -> -1.
    /// Branchless arithmetic — the previous 4-way `match` was a jump table
    /// indexed by secret sk bits.
    pub fn decode(input: &[u8]) -> Result<Self, &'static str> {
        let enc = r3_encoded_bytes(P);
        if input.len() < enc {
            return Err("R3::decode: buffer too small");
        }
        let mut r = R3(SecretArray::new());
        for i in 0..P {
            let byte_idx = i / 4;
            let bit_off = 2 * (i % 4);
            let bits = (input[byte_idx] >> bit_off) & 3;
            let b = i8::from_ne_bytes([bits]);
            r.0[i] = b.wrapping_sub(1).wrapping_sub(3 * ((b >> 1) & (b & 1)));
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks the byte-count contract of the binary-tree encoding against the
    /// six NTRU Prime parameter sets shared by the sntrup and ntruplr crates.
    ///
    /// Values are from the reference Encode simulation (identical across the
    /// former sntrup/ntruplr copies and this merged implementation), and are
    /// exercised end-to-end by both crates' byte-for-byte KATs.
    #[test]
    fn encoded_bytes_match_parameter_sets() {
        let params = [
            (653usize, 4621i16),
            (761, 4591),
            (857, 5167),
            (953, 6343),
            (1013, 7177),
            (1277, 7879),
        ];
        let expected_full = [994, 1158, 1322, 1505, 1623, 2067];
        let expected_rounded = [865, 1007, 1152, 1317, 1423, 1815];
        for (i, (p, q)) in params.iter().enumerate() {
            assert_eq!(
                rq_encoded_bytes(*p, *q),
                expected_full[i],
                "rq_encoded_bytes mismatch for p={p} q={q}"
            );
            assert_eq!(
                rq_rounded_bytes(*p, *q),
                expected_rounded[i],
                "rq_rounded_bytes mismatch for p={p} q={q}"
            );
        }
        assert_eq!(r3_encoded_bytes(653), (653usize * 2).div_ceil(8));
        assert_eq!(r3_encoded_bytes(1277), (1277usize * 2).div_ceil(8));
    }
}
