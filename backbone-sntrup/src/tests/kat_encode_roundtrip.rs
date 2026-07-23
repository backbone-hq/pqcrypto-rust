//! Known-answer tests for SNTRUP Rounded encoding.

#[cfg(test)]
mod sntrup653_kat {
    use crate::poly::Rq;
    use backbone_pqcrypto_internals::secret::SecretArray;

    const P: usize = 653;
    const Q: i16 = 4621;
    const QS: i16 = 4621 / 2;

    fn make_test_poly() -> [i16; P] {
        const SEED: i32 = 123;
        let mut coeffs = [0i16; P];
        for i in 0..P {
            let raw = ((i as i32 * 7 + SEED) * 3) % i32::from(Q - 1);
            let c = raw - i32::from(QS);
            coeffs[i] = c as i16;
        }
        coeffs
    }

    #[test]
    fn kat_encode_rounded() {
        let coeffs = make_test_poly();
        let rq = Rq::<P, Q>(SecretArray::from_array(coeffs));
        let rounded = rq.round3();
        let encoded = rounded.encode_rounded();

        let expected = include_bytes!("../../tests/vectors/sntrup653_encode.bin");

        assert_eq!(
            encoded,
            expected,
            "sntrup653 KAT mismatch: got {} bytes, expected {} bytes",
            encoded.len(),
            expected.len(),
        );
    }

    #[test]
    fn kat_decode_roundtrip() {
        let coeffs = make_test_poly();
        let rq = Rq::<P, Q>(SecretArray::from_array(coeffs));
        let rounded = rq.round3();
        let encoded = rounded.encode_rounded();
        let decoded = Rq::<P, Q>::decode_rounded(&encoded).unwrap();
        assert_eq!(rounded, decoded, "sntrup653 decode roundtrip mismatch");
    }
}

#[cfg(test)]
mod sntrup761_kat {
    use crate::poly::Rq;
    use backbone_pqcrypto_internals::secret::SecretArray;

    const P: usize = 761;
    const Q: i16 = 4591;
    const QS: i16 = 4591 / 2;

    fn make_test_poly() -> [i16; P] {
        const SEED: i32 = 456;
        let mut coeffs = [0i16; P];
        for i in 0..P {
            let raw = ((i as i32 * 7 + SEED) * 3) % i32::from(Q - 1);
            let c = raw - i32::from(QS);
            coeffs[i] = c as i16;
        }
        coeffs
    }

    #[test]
    fn kat_encode_rounded() {
        let coeffs = make_test_poly();
        let rq = Rq::<P, Q>(SecretArray::from_array(coeffs));
        let rounded = rq.round3();
        let encoded = rounded.encode_rounded();

        let expected = include_bytes!("../../tests/vectors/sntrup761_encode.bin");

        assert_eq!(
            encoded,
            expected,
            "sntrup761 KAT mismatch: got {} bytes, expected {} bytes",
            encoded.len(),
            expected.len(),
        );
    }

    #[test]
    fn kat_decode_roundtrip() {
        let coeffs = make_test_poly();
        let rq = Rq::<P, Q>(SecretArray::from_array(coeffs));
        let rounded = rq.round3();
        let encoded = rounded.encode_rounded();
        let decoded = Rq::<P, Q>::decode_rounded(&encoded).unwrap();
        assert_eq!(rounded, decoded, "sntrup761 decode roundtrip mismatch");
    }
}

#[cfg(test)]
mod sntrup857_kat {
    use crate::poly::Rq;
    use backbone_pqcrypto_internals::secret::SecretArray;

    const P: usize = 857;
    const Q: i16 = 5167;
    const QS: i16 = 5167 / 2;

    fn make_test_poly() -> [i16; P] {
        const SEED: i32 = 789;
        let mut coeffs = [0i16; P];
        for i in 0..P {
            let raw = ((i as i32 * 7 + SEED) * 3) % i32::from(Q - 1);
            let c = raw - i32::from(QS);
            coeffs[i] = c as i16;
        }
        coeffs
    }

    #[test]
    fn kat_encode_rounded() {
        let coeffs = make_test_poly();
        let rq = Rq::<P, Q>(SecretArray::from_array(coeffs));
        let rounded = rq.round3();
        let encoded = rounded.encode_rounded();

        let expected = include_bytes!("../../tests/vectors/sntrup857_encode.bin");

        assert_eq!(
            encoded,
            expected,
            "sntrup857 KAT mismatch: got {} bytes, expected {} bytes",
            encoded.len(),
            expected.len(),
        );
    }

    #[test]
    fn kat_decode_roundtrip() {
        let coeffs = make_test_poly();
        let rq = Rq::<P, Q>(SecretArray::from_array(coeffs));
        let rounded = rq.round3();
        let encoded = rounded.encode_rounded();
        let decoded = Rq::<P, Q>::decode_rounded(&encoded).unwrap();
        assert_eq!(rounded, decoded, "sntrup857 decode roundtrip mismatch");
    }
}
