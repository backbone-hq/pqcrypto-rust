//! Polynomial arithmetic in Rq and R3 for NTRU LPRime.
//!
//! Rq = Z/qZ[x]/(x^p - x - 1)
//! R3 = GF(3)[x]/(x^p - x - 1)
//!
//! Thin re-export of the shared NTRU Prime implementation in
//! `backbone_pqcrypto_internals::ntrup`; kept as a module so internal call
//! sites (`crate::poly::*`) and the variant tests below stay in one place.

pub(crate) use backbone_pqcrypto_internals::ntrup::{
    modq_freeze, qshift, r3_encoded_bytes, rq_rounded_bytes, Rq, R3,
};

#[cfg(test)]
mod tests {
    #![allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss
    )]
    use super::*;
    use alloc::vec;
    use backbone_pqcrypto_internals::secret::SecretArray;

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
    fn test_r3_encode_branchless_mapping() {
        // Locks the constant-time encoding contract: -1 -> 0b00, 0 -> 0b01, 1 -> 0b10
        // (2 bits per coefficient, little-endian within each byte).
        const P: usize = 4; // one byte holds all four coefficients
        let mut poly = R3::<P>(SecretArray::new());
        poly.0[0] = -1;
        poly.0[1] = 0;
        poly.0[2] = 1;
        poly.0[3] = -1;
        let mut buf = vec![0u8; r3_encoded_bytes(P)];
        poly.encode(&mut buf).unwrap();
        // bits 0-1: -1 -> 00; bits 2-3: 0 -> 01; bits 4-5: 1 -> 10; bits 6-7: -1 -> 00
        assert_eq!(buf[0], 0b0010_0100);
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
