//! SPHINCS+ signature negative tests.
//!
//! Verifies that verification correctly rejects invalid inputs:
//! - Corrupted message
//! - Wrong public key
//! - Corrupted signature bytes
//! - Truncated signature (boundary case: empty sig, half-length sig)
//! - Empty message roundtrip (positive sanity check)

use pqcrypto_sphincs::params::Params;
use pqcrypto_sphincs::params::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s,
};
use pqcrypto_sphincs::sha2_128f;
use pqcrypto_sphincs::sha2_128s;
use pqcrypto_sphincs::sha2_192f;
use pqcrypto_sphincs::sha2_192s;
use pqcrypto_sphincs::sha2_256f;
use pqcrypto_sphincs::sha2_256s;
use pqcrypto_sphincs::shake128f;
use pqcrypto_sphincs::shake128s;
use pqcrypto_sphincs::shake192f;
use pqcrypto_sphincs::shake192s;
use pqcrypto_sphincs::shake256f;
use pqcrypto_sphincs::shake256s;

macro_rules! negative_tests {
    ($test_name:ident, $module:ident, $variant:ty) => {
        #[test]
        fn $test_name() {
            let seed = vec![0x42u8; <$variant>::SEED_BYTES];
            let msg = b"hello sphincs negative test";

            // --- corrupted message ---
            let (pk, sk) = $module::keygen(&seed).unwrap();
            let sig = $module::sign(&sk, msg).unwrap();
            assert!($module::verify(&pk, msg, &sig));
            let mut bad_msg = msg.to_vec();
            bad_msg[0] ^= 0xff;
            assert!(
                !$module::verify(&pk, &bad_msg, &sig),
                "verify should reject corrupted message"
            );

            // --- wrong public key ---
            let seed_b = vec![0xabu8; <$variant>::SEED_BYTES];
            let (pk_b, _) = $module::keygen(&seed_b).unwrap();
            assert!(
                !$module::verify(&pk_b, msg, &sig),
                "verify should reject wrong public key"
            );

            // --- corrupted signature ---
            let (pk2, sk2) = $module::keygen(&seed).unwrap();
            let sig2 = $module::sign(&sk2, msg).unwrap();
            assert!($module::verify(&pk2, msg, &sig2));
            if sig2.sig.len() > 10 {
                let mut bad_bytes = sig2.sig.clone();
                bad_bytes[8] ^= 0x01;
                let bad_sig = $module::Signature { sig: bad_bytes };
                assert!(
                    !$module::verify(&pk2, msg, &bad_sig),
                    "verify should reject corrupted sig"
                );
            }

            // --- truncated signature ---
            assert!($module::verify(&pk2, msg, &sig2));
            let empty_sig = $module::Signature { sig: vec![] };
            assert!(
                !$module::verify(&pk2, msg, &empty_sig),
                "verify should reject empty sig"
            );
            let half_bytes = sig2.sig[..sig2.sig.len() / 2].to_vec();
            let half_sig = $module::Signature { sig: half_bytes };
            assert!(
                !$module::verify(&pk2, msg, &half_sig),
                "verify should reject truncated sig"
            );

            // --- empty message roundtrip ---
            let (pk3, sk3) = $module::keygen(&seed).unwrap();
            let sig3 = $module::sign(&sk3, b"").unwrap();
            assert!(
                $module::verify(&pk3, b"", &sig3),
                "empty message should verify"
            );
        }
    };
}

// SHAKE variants
negative_tests!(shake128s_negative, shake128s, Shake128s);
negative_tests!(shake128f_negative, shake128f, Shake128f);
negative_tests!(shake192s_negative, shake192s, Shake192s);
negative_tests!(shake192f_negative, shake192f, Shake192f);
negative_tests!(shake256s_negative, shake256s, Shake256s);
negative_tests!(shake256f_negative, shake256f, Shake256f);

// SHA-2 variants
negative_tests!(sha2_128s_negative, sha2_128s, Sha2_128s);
negative_tests!(sha2_128f_negative, sha2_128f, Sha2_128f);
negative_tests!(sha2_192s_negative, sha2_192s, Sha2_192s);
negative_tests!(sha2_192f_negative, sha2_192f, Sha2_192f);
negative_tests!(sha2_256s_negative, sha2_256s, Sha2_256s);
negative_tests!(sha2_256f_negative, sha2_256f, Sha2_256f);

#[test]
fn shake128s_rejects_malformed_raw_inputs_without_panicking() {
    let seed = vec![0x42u8; <Shake128s>::SEED_BYTES];
    let (pk, sk) = shake128s::keygen(&seed).unwrap();
    let msg = b"malformed raw input";
    let sig = shake128s::sign_deterministic(&sk, msg, &[7u8; <Shake128s>::N]).unwrap();

    assert!(shake128s::PublicKey::from_bytes(&pk.pk[..pk.pk.len() - 1]).is_err());
    assert!(shake128s::SecretKey::from_bytes(&sk.as_ref()[..sk.as_ref().len() - 1]).is_err());
    assert!(shake128s::Signature::from_bytes(&sig.sig[..sig.sig.len() - 1]).is_err());
    assert!(shake128s::keygen_checked(&seed[..seed.len() - 1]).is_err());

    let bad_pk = shake128s::PublicKey { pk: vec![0u8; 1] };
    let bad_sk = shake128s::SecretKey::from_bytes(&[0u8; <Shake128s>::SK_BYTES]).unwrap();
    let bad_sig = shake128s::Signature { sig: vec![0u8; 1] };

    assert!(!shake128s::verify(&bad_pk, msg, &sig));
    assert!(shake128s::verify_result(&bad_pk, msg, &sig).is_err());
    assert!(shake128s::verify_result(&pk, msg, &bad_sig).is_err());
    let bad_sig_from_bad_sk = shake128s::sign(&bad_sk, msg).unwrap();
    assert!(!shake128s::verify(&pk, msg, &bad_sig_from_bad_sk));
}

#[test]
fn shake128s_optrand_length_is_variant_n() {
    let seed = vec![0x42u8; <Shake128s>::SEED_BYTES];
    let (pk, sk) = shake128s::keygen(&seed).unwrap();
    let msg = b"optrand length";

    let sig = shake128s::sign_deterministic(&sk, msg, &[1u8; <Shake128s>::N]).unwrap();
    assert!(shake128s::verify(&pk, msg, &sig));
    assert!(shake128s::sign_deterministic(&sk, msg, &[1u8; 32]).is_err());
}

#[test]
fn shake128s_context_and_prehash_are_domain_separated() {
    let seed = vec![0x42u8; <Shake128s>::SEED_BYTES];
    let (pk, sk) = shake128s::keygen(&seed).unwrap();
    let msg = b"context separated message";
    let optrand = [3u8; <Shake128s>::N];

    let sig = shake128s::sign_deterministic_with_context(&sk, msg, b"ctx-a", &optrand).unwrap();
    assert!(shake128s::verify_with_context(&pk, msg, &sig, b"ctx-a"));
    assert!(!shake128s::verify_with_context(&pk, msg, &sig, b"ctx-b"));
    assert!(!shake128s::verify(&pk, msg, &sig));

    let hash_sig =
        shake128s::sign_prehashed_shake256_with_context(&sk, msg, b"ctx-a", &optrand).unwrap();
    assert!(shake128s::verify_prehashed_shake256_with_context(
        &pk, msg, &hash_sig, b"ctx-a"
    ));
    assert!(!shake128s::verify_prehashed_shake256_with_context(
        &pk, msg, &hash_sig, b"ctx-b"
    ));
}

#[test]
fn shake128s_signing_seed_and_randomness_affect_signature() {
    let seed = vec![0x42u8; <Shake128s>::SEED_BYTES];
    let (pk, sk) = shake128s::keygen(&seed).unwrap();
    let msg = b"seed sensitivity";

    let sig_a = shake128s::sign_deterministic(&sk, msg, &[1u8; <Shake128s>::N]).unwrap();
    let sig_b = shake128s::sign_deterministic(&sk, msg, &[2u8; <Shake128s>::N]).unwrap();
    assert_ne!(sig_a.sig, sig_b.sig);
    assert!(shake128s::verify(&pk, msg, &sig_a));
    assert!(shake128s::verify(&pk, msg, &sig_b));

    let random_a = shake128s::sign(&sk, msg).unwrap();
    let random_b = shake128s::sign(&sk, msg).unwrap();
    assert_ne!(random_a.sig, random_b.sig);
    assert!(shake128s::verify(&pk, msg, &random_a));
    assert!(shake128s::verify(&pk, msg, &random_b));
}
