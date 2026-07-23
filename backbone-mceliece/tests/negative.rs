//! McEliece KEM negative tests.
//! GFBITS=12 only (348864, 348864f). GFBITS=13 variants still use legacy API.

macro_rules! negative_tests {
    ($variant:ident, $name:literal) => {
        mod $variant {
            use backbone_mceliece::$variant::*;

            fn roundtrip() -> (PublicKey, SecretKey, Vec<u8>, [u8; 32]) {
                let seed = [0x42u8; 32];
                let (pk, sk) = keypair_from_seed(&seed).expect("keygen");
                let r_seed = [0x42u8; 32];
                let enc = encaps_deterministic(&pk, &r_seed).expect("encaps");
                let ss = decaps(&sk, &enc.ciphertext).expect("decaps");
                (pk, sk, enc.ciphertext.to_vec(), ss)
            }

            #[test]
            fn negative_wrong_key() {
                let (_pk_a, _sk_a, ct, ss_expected) = roundtrip();
                let seed_b = [0x99u8; 32];
                let (_, sk_b) = keypair_from_seed(&seed_b).expect("keygen B");
                let ss_wrong = decaps(&sk_b, &ct).expect("decaps with wrong sk");
                assert_ne!(&ss_wrong, &ss_expected, "wrong key should differ");
            }

            #[test]
            fn negative_corrupted_ciphertext() {
                let (_pk, sk, ct, ss_expected) = roundtrip();
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
            fn negative_invalid_ciphertext_length() {
                let (_pk, sk, ct, _ss) = roundtrip();
                assert!(decaps(&sk, &[]).is_err(), "empty ct should error");
                assert!(
                    decaps(&sk, &ct[..ct.len() / 2]).is_err(),
                    "truncated ct should error"
                );
            }

            #[test]
            fn negative_invalid_secret_key_length() {
                let (_pk, sk, ct, _ss) = roundtrip();
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
        }
    };
}

negative_tests!(mceliece348864, "mceliece348864");
negative_tests!(mceliece348864f, "mceliece348864f");
negative_tests!(mceliece460896, "mceliece460896");
negative_tests!(mceliece460896f, "mceliece460896f");
negative_tests!(mceliece6688128, "mceliece6688128");
negative_tests!(mceliece6688128f, "mceliece6688128f");
negative_tests!(mceliece6960119, "mceliece6960119");
negative_tests!(mceliece6960119f, "mceliece6960119f");
negative_tests!(mceliece8192128, "mceliece8192128");
negative_tests!(mceliece8192128f, "mceliece8192128f");
