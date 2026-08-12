//! Negative tests: malformed inputs must be rejected by the public API.
//!
//! Streamlined NTRU Prime validates byte lengths (public key, secret key,
//! ciphertext) but has no canonical-encoding rejection beyond lengths, so
//! these tests assert the length checks and deterministic tamper behavior
//! (a corrupted ciphertext must never silently reproduce the same shared
//! secret). Garbage-input robustness (no panics) lives in `validation.rs`.

use backbone_pqcrypto_internals::kat::FixedRng;
use backbone_sntrup::{sntrup1277, sntrup653, sntrup761};

macro_rules! negative_tests {
    ($setup:ident, $variant:ident, $wrong_len_pk:ident, $wrong_len_sk:ident, $wrong_len_ct:ident, $corrupted_ct:ident) => {
        fn $setup() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
            let (pk, sk) =
                $variant::keygen_with_rng(&mut FixedRng::new(vec![3u8; 48])).expect("keygen");
            let enc =
                $variant::encaps_with_rng(&pk, &mut FixedRng::new(vec![7u8; 48])).expect("encaps");
            (
                pk.pk.clone(),
                sk.as_ref().to_vec(),
                enc.ciphertext.clone(),
                enc.shared_secret.to_vec(),
            )
        }

        #[test]
        fn $wrong_len_pk() {
            let (pk, _sk, _ct, _ss) = $setup();
            assert!($variant::PublicKey::from_bytes(&pk).is_ok());
            assert!($variant::PublicKey::from_bytes(&pk[..pk.len() - 1]).is_err());
            let mut too_long = pk;
            too_long.push(0);
            assert!($variant::PublicKey::from_bytes(&too_long).is_err());
        }

        #[test]
        fn $wrong_len_sk() {
            let (_pk, sk, _ct, _ss) = $setup();
            assert!($variant::SecretKey::from_bytes(&sk).is_ok());
            assert!($variant::SecretKey::from_bytes(&sk[..sk.len() - 1]).is_err());
            let mut too_long = sk;
            too_long.push(0);
            assert!($variant::SecretKey::from_bytes(&too_long).is_err());
        }

        #[test]
        fn $wrong_len_ct() {
            let (_pk, sk, ct, _ss) = $setup();
            let sk = $variant::SecretKey::from_bytes(&sk).expect("valid sk");
            assert!($variant::decaps(&sk, &ct).is_ok());
            assert!($variant::decaps(&sk, &ct[..ct.len() - 1]).is_err());
            let mut too_long = ct;
            too_long.push(0);
            assert!($variant::decaps(&sk, &too_long).is_err());
        }

        #[test]
        fn $corrupted_ct() {
            let (_pk, sk, ct, ss) = $setup();
            let sk = $variant::SecretKey::from_bytes(&sk).expect("valid sk");
            for i in 0..ct.len().min(4) {
                let mut corrupted = ct.clone();
                corrupted[i] ^= 0x01;
                let dec = $variant::decaps(&sk, &corrupted).expect("decaps corrupted ct");
                assert_ne!(
                    &dec[..],
                    ss.as_slice(),
                    "single-bit corruption at byte {i} must change the shared secret"
                );
            }
        }
    };
}

negative_tests!(
    sntrup653_setup,
    sntrup653,
    sntrup653_rejects_wrong_length_public_key,
    sntrup653_rejects_wrong_length_secret_key,
    sntrup653_rejects_wrong_length_ciphertext,
    sntrup653_corrupted_ciphertext_changes_shared_secret
);
negative_tests!(
    sntrup761_setup,
    sntrup761,
    sntrup761_rejects_wrong_length_public_key,
    sntrup761_rejects_wrong_length_secret_key,
    sntrup761_rejects_wrong_length_ciphertext,
    sntrup761_corrupted_ciphertext_changes_shared_secret
);
negative_tests!(
    sntrup1277_setup,
    sntrup1277,
    sntrup1277_rejects_wrong_length_public_key,
    sntrup1277_rejects_wrong_length_secret_key,
    sntrup1277_rejects_wrong_length_ciphertext,
    sntrup1277_corrupted_ciphertext_changes_shared_secret
);
