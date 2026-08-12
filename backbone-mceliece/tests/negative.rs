//! McEliece KEM negative tests.

use backbone_pqcrypto_internals::kat::FixedRng;

macro_rules! negative_tests {
    ($setup:ident, $variant:ident, $wrong_key:ident, $corrupted_ct:ident, $invalid_ct:ident, $invalid_sk:ident, $invalid_pk:ident) => {
        fn $setup() -> (
            backbone_mceliece::$variant::PublicKey,
            backbone_mceliece::$variant::SecretKey,
            Vec<u8>,
            [u8; 32],
        ) {
            use backbone_mceliece::$variant::*;
            let seed = [0x42u8; 48];
            let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).expect("keygen");
            let r_seed = [0x42u8; 48];
            let enc = encaps_with_rng(&pk, &mut FixedRng::new(r_seed.to_vec())).expect("encaps");
            let ss = decaps(&sk, &enc.ciphertext).expect("decaps");
            (pk, sk, enc.ciphertext.to_vec(), ss)
        }

        #[test]
        fn $wrong_key() {
            use backbone_mceliece::$variant::*;
            let (_pk_a, _sk_a, ct, ss_expected) = $setup();
            let seed_b = [0x99u8; 48];
            let (_, sk_b) = keygen_with_rng(&mut FixedRng::new(seed_b.to_vec())).expect("keygen B");
            let ss_wrong = decaps(&sk_b, &ct).expect("decaps with wrong sk");
            assert_ne!(&ss_wrong, &ss_expected, "wrong key should differ");
        }

        #[test]
        fn $corrupted_ct() {
            use backbone_mceliece::$variant::*;
            let (_pk, sk, ct, ss_expected) = $setup();
            for i in 0..ct.len().min(4) {
                for bit in 0..8 {
                    let mut ct_corrupted = ct.clone();
                    ct_corrupted[i] ^= 1 << bit;
                    let ss_corrupted = decaps(&sk, &ct_corrupted).expect("decaps corrupted ct");
                    assert_ne!(
                        &ss_corrupted, &ss_expected,
                        "corrupted ct byte {i} bit {bit}"
                    );
                }
            }
        }

        #[test]
        fn $invalid_ct() {
            use backbone_mceliece::$variant::*;
            let (_pk, sk, ct, _ss) = $setup();
            assert!(decaps(&sk, &[]).is_err(), "empty ct should error");
            assert!(
                decaps(&sk, &ct[..ct.len() / 2]).is_err(),
                "truncated ct should error"
            );
        }

        #[test]
        fn $invalid_sk() {
            use backbone_mceliece::$variant::*;
            let (_pk, sk, ct, _ss) = $setup();
            assert!(
                SecretKey::from_bytes(&[]).is_err(),
                "empty sk should be rejected"
            );
            assert!(
                SecretKey::from_bytes(&sk.as_ref()[..sk.as_ref().len() / 2]).is_err(),
                "truncated sk should be rejected"
            );
            let garbage_sk = SecretKey::from_bytes(&vec![0xABu8; sk.as_ref().len()]).unwrap();
            let ss = decaps(&garbage_sk, &ct).expect("garbage sk decaps should fall back");
            assert_ne!(ss, [0u8; 32], "garbage sk should produce non-zero fallback");
        }

        #[test]
        fn $invalid_pk() {
            use backbone_mceliece::$variant::*;
            // B1 regression: a short/oversized pk must return an error, never
            // panic (the pre-fix `encaps` skipped the pk length check).
            let (pk_ok, _sk_ok, _ct, _ss) = $setup();
            let pk_len = pk_ok.pk.len();
            let short_pk = PublicKey { pk: vec![0u8; 1] };
            assert!(
                encaps(&short_pk).is_err(),
                "short pk should error, not panic"
            );
            let long_pk = PublicKey {
                pk: vec![0u8; pk_len + 1],
            };
            assert!(encaps(&long_pk).is_err(), "oversized pk should error");
            // Garbage but correctly-sized pk: encaps must not panic.
            let garbage_pk = PublicKey {
                pk: vec![0xABu8; pk_len],
            };
            let _ = encaps(&garbage_pk);
        }
    };
}

negative_tests!(
    mceliece348864_setup,
    mceliece348864,
    mceliece348864_negative_wrong_key,
    mceliece348864_negative_corrupted_ct,
    mceliece348864_negative_invalid_ct_len,
    mceliece348864_negative_invalid_sk_len,
    mceliece348864_negative_invalid_pk
);
negative_tests!(
    mceliece348864f_setup,
    mceliece348864f,
    mceliece348864f_negative_wrong_key,
    mceliece348864f_negative_corrupted_ct,
    mceliece348864f_negative_invalid_ct_len,
    mceliece348864f_negative_invalid_sk_len,
    mceliece348864f_negative_invalid_pk
);
negative_tests!(
    mceliece460896_setup,
    mceliece460896,
    mceliece460896_negative_wrong_key,
    mceliece460896_negative_corrupted_ct,
    mceliece460896_negative_invalid_ct_len,
    mceliece460896_negative_invalid_sk_len,
    mceliece460896_negative_invalid_pk
);
negative_tests!(
    mceliece460896f_setup,
    mceliece460896f,
    mceliece460896f_negative_wrong_key,
    mceliece460896f_negative_corrupted_ct,
    mceliece460896f_negative_invalid_ct_len,
    mceliece460896f_negative_invalid_sk_len,
    mceliece460896f_negative_invalid_pk
);
negative_tests!(
    mceliece6688128_setup,
    mceliece6688128,
    mceliece6688128_negative_wrong_key,
    mceliece6688128_negative_corrupted_ct,
    mceliece6688128_negative_invalid_ct_len,
    mceliece6688128_negative_invalid_sk_len,
    mceliece6688128_negative_invalid_pk
);
negative_tests!(
    mceliece6688128f_setup,
    mceliece6688128f,
    mceliece6688128f_negative_wrong_key,
    mceliece6688128f_negative_corrupted_ct,
    mceliece6688128f_negative_invalid_ct_len,
    mceliece6688128f_negative_invalid_sk_len,
    mceliece6688128f_negative_invalid_pk
);
negative_tests!(
    mceliece6960119_setup,
    mceliece6960119,
    mceliece6960119_negative_wrong_key,
    mceliece6960119_negative_corrupted_ct,
    mceliece6960119_negative_invalid_ct_len,
    mceliece6960119_negative_invalid_sk_len,
    mceliece6960119_negative_invalid_pk
);
negative_tests!(
    mceliece6960119f_setup,
    mceliece6960119f,
    mceliece6960119f_negative_wrong_key,
    mceliece6960119f_negative_corrupted_ct,
    mceliece6960119f_negative_invalid_ct_len,
    mceliece6960119f_negative_invalid_sk_len,
    mceliece6960119f_negative_invalid_pk
);
negative_tests!(
    mceliece8192128_setup,
    mceliece8192128,
    mceliece8192128_negative_wrong_key,
    mceliece8192128_negative_corrupted_ct,
    mceliece8192128_negative_invalid_ct_len,
    mceliece8192128_negative_invalid_sk_len,
    mceliece8192128_negative_invalid_pk
);
negative_tests!(
    mceliece8192128f_setup,
    mceliece8192128f,
    mceliece8192128f_negative_wrong_key,
    mceliece8192128f_negative_corrupted_ct,
    mceliece8192128f_negative_invalid_ct_len,
    mceliece8192128f_negative_invalid_sk_len,
    mceliece8192128f_negative_invalid_pk
);
