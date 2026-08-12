//! Public Classic McEliece roundtrip tests using system randomness for
//! keygen and a fixed encaps seed, plus a chained 100-round depth test
//! per variant (migrated from the pinned transcript tests).

use backbone_mceliece::{
    mceliece348864, mceliece348864f, mceliece460896, mceliece460896f, mceliece6688128,
    mceliece6688128f, mceliece6960119, mceliece6960119f, mceliece8192128, mceliece8192128f,
};
use backbone_pqcrypto_internals::kat::FixedRng;

#[test]
fn mceliece348864_roundtrip() {
    let (pk, sk) = mceliece348864::keygen().expect("keygen");
    let enc =
        mceliece348864::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48])).expect("encaps");
    let dec = mceliece348864::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece348864f_roundtrip() {
    let (pk, sk) = mceliece348864f::keygen().expect("keygen");
    let enc = mceliece348864f::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48]))
        .expect("encaps");
    let dec = mceliece348864f::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece460896_roundtrip() {
    let (pk, sk) = mceliece460896::keygen().expect("keygen");
    let enc =
        mceliece460896::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48])).expect("encaps");
    let dec = mceliece460896::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece460896f_roundtrip() {
    let (pk, sk) = mceliece460896f::keygen().expect("keygen");
    let enc = mceliece460896f::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48]))
        .expect("encaps");
    let dec = mceliece460896f::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece6688128_roundtrip() {
    let (pk, sk) = mceliece6688128::keygen().expect("keygen");
    let enc = mceliece6688128::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48]))
        .expect("encaps");
    let dec = mceliece6688128::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece6688128f_roundtrip() {
    let (pk, sk) = mceliece6688128f::keygen().expect("keygen");
    let enc = mceliece6688128f::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48]))
        .expect("encaps");
    let dec = mceliece6688128f::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece6960119_roundtrip() {
    let (pk, sk) = mceliece6960119::keygen().expect("keygen");
    let enc = mceliece6960119::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48]))
        .expect("encaps");
    let dec = mceliece6960119::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece6960119f_roundtrip() {
    let (pk, sk) = mceliece6960119f::keygen().expect("keygen");
    let enc = mceliece6960119f::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48]))
        .expect("encaps");
    let dec = mceliece6960119f::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece8192128_roundtrip() {
    let (pk, sk) = mceliece8192128::keygen().expect("keygen");
    let enc = mceliece8192128::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48]))
        .expect("encaps");
    let dec = mceliece8192128::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece8192128f_roundtrip() {
    let (pk, sk) = mceliece8192128f::keygen().expect("keygen");
    let enc = mceliece8192128f::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48]))
        .expect("encaps");
    let dec = mceliece8192128f::decaps(&sk, &enc.ciphertext).expect("decaps");
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

/// Chained 100-round deterministic roundtrip per variant: random-input
/// depth across keygen/encaps/decaps without a pinned hash (the former
/// transcript tests' hash only added pin-maintenance, not coverage).
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
                    backbone_mceliece::$variant::keygen_with_rng(&mut FixedRng::new(seed.to_vec()))
                        .expect("keygen");
                let enc = backbone_mceliece::$variant::encaps_with_rng(
                    &pk,
                    &mut FixedRng::new(seed.to_vec()),
                )
                .expect("encaps");
                let dec =
                    backbone_mceliece::$variant::decaps(&sk, &enc.ciphertext).expect("decaps");
                assert_eq!(enc.shared_secret, dec);
            }
        }
    };
}

depth_test!(mceliece348864_depth, mceliece348864);
depth_test!(mceliece348864f_depth, mceliece348864f);
depth_test!(mceliece460896_depth, mceliece460896);
depth_test!(mceliece460896f_depth, mceliece460896f);
depth_test!(mceliece6688128_depth, mceliece6688128);
depth_test!(mceliece6688128f_depth, mceliece6688128f);
depth_test!(mceliece6960119_depth, mceliece6960119);
depth_test!(mceliece6960119f_depth, mceliece6960119f);
depth_test!(mceliece8192128_depth, mceliece8192128);
depth_test!(mceliece8192128f_depth, mceliece8192128f);
