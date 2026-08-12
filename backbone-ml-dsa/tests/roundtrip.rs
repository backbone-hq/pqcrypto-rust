//! Roundtrip tests for ML-DSA (FIPS 204): pure-mode and HashML-DSA pre-hash
//! sign → verify, including wrong-context/wrong-hash rejection. Byte-exact
//! conformance lives in `kats.rs`.
//!
//! HashML-DSA is roundtrip-only: the ACVP pre-hash vectors predate the
//! `decode_poly_t0_from_bits` `>=` fix and were removed; regenerate them via
//! `tools/rsp-converter/acvp-to-rsp.py` to restore byte-exact pre-hash KATs.

use backbone_ml_dsa::mldsa44;
use backbone_ml_dsa::mldsa65;
use backbone_ml_dsa::mldsa87;
use backbone_ml_dsa::HashAlgorithm;
use backbone_pqcrypto_internals::kat::FixedRng;

// 1. Pure-mode roundtrips.

macro_rules! roundtrip_test {
    ($name:ident, $variant:ident) => {
        #[test]
        fn $name() {
            let (pk, sk) = $variant::keygen().unwrap();
            let msg = b"hello world";
            let sig = $variant::sign(&sk, msg, None, None).unwrap();
            assert!($variant::verify(&pk, msg, &sig, None, None).is_ok());
        }
    };
}

roundtrip_test!(test_ml_dsa_44_roundtrip, mldsa44);
roundtrip_test!(test_ml_dsa_65_roundtrip, mldsa65);
roundtrip_test!(test_ml_dsa_87_roundtrip, mldsa87);

// 2. HashML-DSA (pre-hash) roundtrips + param-mismatch rejection.

const ALL_HASHES: &[HashAlgorithm] = &[
    HashAlgorithm::Sha224,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha512,
    HashAlgorithm::Sha512_224,
    HashAlgorithm::Sha512_256,
    HashAlgorithm::Sha3_224,
    HashAlgorithm::Sha3_256,
    HashAlgorithm::Sha3_384,
    HashAlgorithm::Sha3_512,
    HashAlgorithm::Shake128,
    HashAlgorithm::Shake256,
];

const MSG: &[u8] = b"HashML-DSA pre-hash roundtrip test message";
const CTX: &[u8] = b"my-context";

fn wrong_hash(h: HashAlgorithm) -> HashAlgorithm {
    if h as u8 == HashAlgorithm::Sha256 as u8 {
        HashAlgorithm::Sha384
    } else {
        HashAlgorithm::Sha256
    }
}

macro_rules! prehash_roundtrip_test {
    ($name:ident, $variant:ident) => {
        #[test]
        fn $name() {
            let seed = [0x42u8; 32];
            let optrand = [0x13u8; 32];
            let (pk, sk) =
                $variant::keygen_with_rng(&mut FixedRng::new(seed.to_vec())).expect("keygen");

            for &hash in ALL_HASHES {
                let sig = $variant::sign_with_rng(
                    &sk,
                    MSG,
                    &mut FixedRng::new(optrand.to_vec()),
                    Some(CTX),
                    Some(hash),
                )
                .unwrap_or_else(|e| panic!("{hash:?}: sign failed: {e}"));

                assert!(
                    $variant::verify(&pk, MSG, &sig, Some(CTX), Some(hash)).is_ok(),
                    "{hash:?}: verify with correct params should succeed",
                );
                assert!(
                    $variant::verify(&pk, MSG, &sig, Some(b"wrong-ctx"), Some(hash)).is_err(),
                    "{hash:?}: verify with wrong context should fail",
                );
                assert!(
                    $variant::verify(&pk, MSG, &sig, Some(CTX), Some(wrong_hash(hash))).is_err(),
                    "{hash:?}: verify with wrong hash should fail",
                );
                assert!(
                    $variant::verify(&pk, MSG, &sig, None, Some(hash)).is_err(),
                    "{hash:?}: verify with no context should fail",
                );
            }
        }
    };
}

prehash_roundtrip_test!(mldsa44_prehash_roundtrip, mldsa44);
prehash_roundtrip_test!(mldsa65_prehash_roundtrip, mldsa65);
prehash_roundtrip_test!(mldsa87_prehash_roundtrip, mldsa87);
