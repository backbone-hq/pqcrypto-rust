//! Public HQC KEM roundtrip tests, plus a chained 100-round depth test
//! per variant (standard depth coverage across KEMs).

use backbone_hqc::{hqc128, hqc192, hqc256};
use backbone_pqcrypto_internals::kat::FixedRng;

#[test]
fn hqc1_public_roundtrip() {
    let (pk, sk) = hqc128::keygen().expect("keygen");
    let enc = hqc128::encaps(&pk).expect("encaps");
    let dec = hqc128::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn hqc3_public_roundtrip() {
    let (pk, sk) = hqc192::keygen().expect("keygen");
    let enc = hqc192::encaps(&pk).expect("encaps");
    let dec = hqc192::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn hqc5_public_roundtrip() {
    let (pk, sk) = hqc256::keygen().expect("keygen");
    let enc = hqc256::encaps(&pk).expect("encaps");
    let dec = hqc256::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

fn shake256<const OUT: usize>(input: &[u8]) -> [u8; OUT] {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    let mut shake = Shake256::default();
    Update::update(&mut shake, input);
    let mut reader = shake.finalize_xof();
    let mut out = [0u8; OUT];
    reader.read(&mut out);
    out
}

/// Chained 100-round deterministic roundtrip per variant.
macro_rules! depth_test {
    ($test_name:ident, $variant:ident) => {
        #[test]
        fn $test_name() {
            const NUM_ROUNDS: usize = 100;
            let seed_init = [
                32u8, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
                73, 74, 75, 76, 77, 78, 79,
            ];
            let mut coins = shake256::<112>(&seed_init);
            for _ in 0..NUM_ROUNDS {
                coins = shake256::<112>(&coins);
                let seed: [u8; 48] = coins[..48].try_into().unwrap();
                let (pk, sk) =
                    backbone_hqc::$variant::keygen_with_rng(&mut FixedRng::new(seed.to_vec()))
                        .expect("keygen");
                let enc =
                    backbone_hqc::$variant::encaps_with_rng(&pk, &mut FixedRng::new(seed.to_vec()))
                        .expect("encaps");
                let dec = backbone_hqc::$variant::decaps(&sk, &enc.ciphertext).expect("decaps");
                assert_eq!(enc.shared_secret, dec);
            }
        }
    };
}

depth_test!(hqc128_depth, hqc128);
depth_test!(hqc192_depth, hqc192);
depth_test!(hqc256_depth, hqc256);
