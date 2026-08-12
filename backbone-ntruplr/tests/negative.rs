//! Negative tests for NTRU LPRime.

use backbone_ntruplr::error::Error;
use backbone_pqcrypto_internals::kat::FixedRng;

macro_rules! negative_tests {
    ($test:ident, $variant:ident, $params:ident) => {
        #[test]
        fn $test() {
            use backbone_ntruplr::params::$params as ParamsT;
            use backbone_ntruplr::params::Params;
            use backbone_ntruplr::$variant::{
                decaps, encaps_with_rng, keygen_with_rng, PublicKey, SecretKey,
            };

            const SK_BYTES: usize = <ParamsT as Params>::SK_BYTES;

            let (pk_a, sk_a) =
                keygen_with_rng(&mut FixedRng::new(vec![0x42u8; 48])).expect("keygen A");
            let (_pk_b, sk_b) =
                keygen_with_rng(&mut FixedRng::new(vec![0x99u8; 48])).expect("keygen B");
            let enc = encaps_with_rng(&pk_a, &mut FixedRng::new(vec![0x13u8; 32]))
                .expect("encaps should succeed");

            let wrong_key_ss = decaps(&sk_b, &enc.ciphertext).expect("decaps should succeed");
            assert_ne!(wrong_key_ss, enc.shared_secret);

            for pos in [
                0usize,
                1,
                enc.ciphertext.len() / 3,
                enc.ciphertext.len() / 2,
                enc.ciphertext.len() - 1,
            ] {
                let mut ct = enc.ciphertext.clone();
                ct[pos] ^= 0xff;
                let tampered_ss = decaps(&SecretKey::from_bytes(sk_a.as_ref()).unwrap(), &ct)
                    .expect("same-length tampered ciphertext uses fallback");
                assert_ne!(tampered_ss, enc.shared_secret, "tampered byte {pos}");
            }

            assert_eq!(
                decaps(&sk_a, &[]).expect_err("empty ct"),
                Error::InvalidCiphertextLength
            );
            assert_eq!(
                decaps(&sk_a, &enc.ciphertext[..enc.ciphertext.len() - 1])
                    .expect_err("truncated ct"),
                Error::InvalidCiphertextLength
            );
            assert_eq!(
                decaps(&sk_a, &[enc.ciphertext.as_slice(), &[0u8]].concat(),)
                    .expect_err("oversized ct"),
                Error::InvalidCiphertextLength
            );

            assert!(SecretKey::from_bytes(&[0u8; 1]).is_err());
            assert!(SecretKey::from_bytes(&vec![0u8; SK_BYTES - 1]).is_err());
            assert!(SecretKey::from_bytes(&vec![0u8; SK_BYTES + 1]).is_err());

            let short_pk = PublicKey {
                pk: pk_a.pk[..pk_a.pk.len() - 1].to_vec(),
            };
            assert_eq!(
                encaps_with_rng(&short_pk, &mut FixedRng::new(vec![0x13u8; 32]))
                    .expect_err("short pk"),
                Error::InvalidKeyLength
            );
        }
    };
}

negative_tests!(ntruplr653_negative, ntruplr653, Ntruplr653);
negative_tests!(ntruplr761_negative, ntruplr761, Ntruplr761);
negative_tests!(ntruplr857_negative, ntruplr857, Ntruplr857);
negative_tests!(ntruplr953_negative, ntruplr953, Ntruplr953);
negative_tests!(ntruplr1013_negative, ntruplr1013, Ntruplr1013);
negative_tests!(ntruplr1277_negative, ntruplr1277, Ntruplr1277);
