//! Public Streamlined NTRU Prime roundtrip tests using system randomness
//! for keygen and a fixed encaps seed, plus a chained 100-round depth test
//! per variant (migrated from the pinned transcript tests).

use backbone_pqcrypto_internals::kat::FixedRng;
use backbone_sntrup::{sntrup1013, sntrup1277, sntrup653, sntrup761, sntrup857, sntrup953};

#[test]
fn sntrup653_roundtrip() {
    let (pk, sk) = sntrup653::keygen().expect("keygen");
    let enc =
        sntrup653::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48])).expect("encaps");
    let dec = sntrup653::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn sntrup761_roundtrip() {
    let (pk, sk) = sntrup761::keygen().expect("keygen");
    let enc =
        sntrup761::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48])).expect("encaps");
    let dec = sntrup761::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn sntrup857_roundtrip() {
    let (pk, sk) = sntrup857::keygen().expect("keygen");
    let enc =
        sntrup857::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48])).expect("encaps");
    let dec = sntrup857::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

macro_rules! roundtrip_test {
    ($test_name:ident, $variant:ident) => {
        #[test]
        fn $test_name() {
            let (pk, sk) = $variant::keygen().expect("keygen");
            let enc = $variant::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48]))
                .expect("encaps");
            let dec = $variant::decaps(&sk, &enc.ciphertext).expect("decaps");
            assert_eq!(enc.shared_secret, dec);
        }
    };
}

roundtrip_test!(sntrup953_roundtrip, sntrup953);
roundtrip_test!(sntrup1013_roundtrip, sntrup1013);
roundtrip_test!(sntrup1277_roundtrip, sntrup1277);

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

/// Chained 100-round deterministic roundtrip per variant (hash-free
/// migration of the former transcript tests).
macro_rules! depth_test {
    ($test_name:ident, $variant:ident) => {
        #[test]
        fn $test_name() {
            const NUM_ROUNDS: usize = 100;
            let seed_init = [
                32u8, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
            ];
            let mut coins = shake256::<96>(&seed_init);
            for _ in 0..NUM_ROUNDS {
                coins = shake256::<96>(&coins);
                let seed: [u8; 48] = coins[..48].try_into().unwrap();
                let r_seed: [u8; 32] = coins[48..80].try_into().unwrap();
                let (pk, sk) =
                    $variant::keygen_with_rng(&mut FixedRng::new(seed.to_vec())).expect("keygen");
                let enc = $variant::encaps_with_rng(&pk, &mut FixedRng::new(r_seed.to_vec()))
                    .expect("encaps");
                let dec = $variant::decaps(&sk, &enc.ciphertext).expect("decaps");
                assert_eq!(enc.shared_secret, dec);
            }
        }
    };
}

depth_test!(sntrup653_depth, sntrup653);
depth_test!(sntrup761_depth, sntrup761);
depth_test!(sntrup857_depth, sntrup857);
depth_test!(sntrup953_depth, sntrup953);
depth_test!(sntrup1013_depth, sntrup1013);
depth_test!(sntrup1277_depth, sntrup1277);
