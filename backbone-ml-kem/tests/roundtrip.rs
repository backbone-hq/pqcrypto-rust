//! Public ML-KEM roundtrip tests using system randomness for keygen and a
//! fixed encaps message, plus a chained 100-round depth test per variant
//! (standard depth coverage across KEMs).

use backbone_ml_kem::{mlkem1024, mlkem512, mlkem768};
use backbone_pqcrypto_internals::kat::FixedRng;

#[test]
fn mlkem512_roundtrip() {
    let (pk, sk) = mlkem512::keygen().expect("keygen");
    let enc = mlkem512::encaps_with_rng(&pk, &mut FixedRng::new(vec![0xabu8; 32])).expect("encaps");
    let dec = mlkem512::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mlkem768_roundtrip() {
    let (pk, sk) = mlkem768::keygen().expect("keygen");
    let enc = mlkem768::encaps_with_rng(&pk, &mut FixedRng::new(vec![0xabu8; 32])).expect("encaps");
    let dec = mlkem768::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mlkem1024_roundtrip() {
    let (pk, sk) = mlkem1024::keygen().expect("keygen");
    let enc =
        mlkem1024::encaps_with_rng(&pk, &mut FixedRng::new(vec![0xabu8; 32])).expect("encaps");
    let dec = mlkem1024::decaps(&sk, &enc.ciphertext).expect("decaps");
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
                let seed: [u8; 64] = coins[..64].try_into().unwrap();
                let r_seed: [u8; 32] = coins[64..96].try_into().unwrap();
                let (pk, sk) =
                    backbone_ml_kem::$variant::keygen_with_rng(&mut FixedRng::new(seed.to_vec()))
                        .expect("keygen");
                let enc = backbone_ml_kem::$variant::encaps_with_rng(
                    &pk,
                    &mut FixedRng::new(r_seed.to_vec()),
                )
                .expect("encaps");
                let dec = backbone_ml_kem::$variant::decaps(&sk, &enc.ciphertext).expect("decaps");
                assert_eq!(enc.shared_secret, dec);
            }
        }
    };
}

depth_test!(mlkem512_depth, mlkem512);
depth_test!(mlkem768_depth, mlkem768);
depth_test!(mlkem1024_depth, mlkem1024);
