//! SPHINCS+ signature negative tests.

use backbone_pqcrypto_internals::kat::FixedRng;
use backbone_sphincs::params::ConstParams;
use backbone_sphincs::params::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s,
};
use backbone_sphincs::sha2_128f;
use backbone_sphincs::sha2_128s;
use backbone_sphincs::sha2_192f;
use backbone_sphincs::sha2_192s;
use backbone_sphincs::sha2_256f;
use backbone_sphincs::sha2_256s;
use backbone_sphincs::shake128f;
use backbone_sphincs::shake128s;
use backbone_sphincs::shake192f;
use backbone_sphincs::shake192s;
use backbone_sphincs::shake256f;
use backbone_sphincs::shake256s;
use backbone_sphincs::HashAlgorithm;
use sha3::{digest::ExtendableOutput, digest::Update, digest::XofReader, Shake256};

macro_rules! negative_tests {
    ($test_name:ident, $module:ident, $variant:ty) => {
        #[test]
        fn $test_name() {
            let seed = vec![0x42u8; <$variant>::SEED_BYTES];
            let msg = b"hello sphincs negative test";

            let (pk, sk) = $module::keygen_with_rng(&mut FixedRng::new(seed.clone())).unwrap();
            let sig = $module::sign(&sk, msg, None, None).unwrap();
            assert!($module::verify(&pk, msg, &sig, None, None).is_ok());
            let mut bad_msg = msg.to_vec();
            bad_msg[0] ^= 0xff;
            assert!(
                $module::verify(&pk, &bad_msg, &sig, None, None).is_err(),
                "verify should reject corrupted message"
            );

            let seed_b = vec![0xabu8; <$variant>::SEED_BYTES];
            let (pk_b, _) = $module::keygen_with_rng(&mut FixedRng::new(seed_b)).unwrap();
            assert!(
                $module::verify(&pk_b, msg, &sig, None, None).is_err(),
                "verify should reject wrong public key"
            );

            let (pk2, sk2) = $module::keygen_with_rng(&mut FixedRng::new(seed.clone())).unwrap();
            let sig2 = $module::sign(&sk2, msg, None, None).unwrap();
            assert!($module::verify(&pk2, msg, &sig2, None, None).is_ok());
            if sig2.sig.len() > 10 {
                let mut bad_bytes = sig2.sig.clone();
                bad_bytes[8] ^= 0x01;
                let bad_sig = $module::Signature { sig: bad_bytes };
                assert!(
                    !$module::verify(&pk2, msg, &bad_sig, None, None).is_ok(),
                    "verify should reject corrupted sig"
                );
            }

            assert!($module::verify(&pk2, msg, &sig2, None, None).is_ok());
            let empty_sig = $module::Signature { sig: vec![] };
            assert!(
                !$module::verify(&pk2, msg, &empty_sig, None, None).is_ok(),
                "verify should reject empty sig"
            );
            let half_bytes = sig2.sig[..sig2.sig.len() / 2].to_vec();
            let half_sig = $module::Signature { sig: half_bytes };
            assert!(
                !$module::verify(&pk2, msg, &half_sig, None, None).is_ok(),
                "verify should reject truncated sig"
            );

            let (pk3, sk3) = $module::keygen_with_rng(&mut FixedRng::new(seed)).unwrap();
            let sig3 = $module::sign(&sk3, b"", None, None).unwrap();
            assert!(
                $module::verify(&pk3, b"", &sig3, None, None).is_ok(),
                "empty message should verify"
            );
        }
    };
}

negative_tests!(shake128s_negative, shake128s, Shake128s);
negative_tests!(shake128f_negative, shake128f, Shake128f);
negative_tests!(shake192s_negative, shake192s, Shake192s);
negative_tests!(shake192f_negative, shake192f, Shake192f);
negative_tests!(shake256s_negative, shake256s, Shake256s);
negative_tests!(shake256f_negative, shake256f, Shake256f);

negative_tests!(sha2_128s_negative, sha2_128s, Sha2_128s);
negative_tests!(sha2_128f_negative, sha2_128f, Sha2_128f);
negative_tests!(sha2_192s_negative, sha2_192s, Sha2_192s);
negative_tests!(sha2_192f_negative, sha2_192f, Sha2_192f);
negative_tests!(sha2_256s_negative, sha2_256s, Sha2_256s);
negative_tests!(sha2_256f_negative, sha2_256f, Sha2_256f);

#[test]
fn shake128s_rejects_malformed_raw_inputs_without_panicking() {
    let seed = vec![0x42u8; <Shake128s>::SEED_BYTES];
    let (pk, sk) = shake128s::keygen_with_rng(&mut FixedRng::new(seed)).unwrap();
    let msg = b"malformed raw input";
    let optrand = vec![7u8; <Shake128s as ConstParams>::N];
    let sig = shake128s::sign_with_rng(&sk, msg, &mut FixedRng::new(optrand), None, None).unwrap();

    assert!(shake128s::PublicKey::from_bytes(&pk.pk[..pk.pk.len() - 1]).is_err());
    assert!(shake128s::SecretKey::from_bytes(&sk.as_ref()[..sk.as_ref().len() - 1]).is_err());
    assert!(shake128s::Signature::from_bytes(&sig.sig[..sig.sig.len() - 1]).is_err());

    let bad_pk = shake128s::PublicKey { pk: vec![0u8; 1] };
    let bad_sk =
        shake128s::SecretKey::from_bytes(&[0u8; <Shake128s as ConstParams>::SK_BYTES]).unwrap();
    let bad_sig = shake128s::Signature { sig: vec![0u8; 1] };

    assert!(shake128s::verify(&bad_pk, msg, &sig, None, None).is_err());
    assert!(shake128s::verify(&pk, msg, &bad_sig, None, None).is_err());
    let bad_sig_from_bad_sk = shake128s::sign(&bad_sk, msg, None, None).unwrap();
    assert!(shake128s::verify(&pk, msg, &bad_sig_from_bad_sk, None, None).is_err());
}

#[test]
fn shake128s_optrand_length_is_variant_n() {
    let seed = vec![0x42u8; <Shake128s>::SEED_BYTES];
    let (pk, sk) = shake128s::keygen_with_rng(&mut FixedRng::new(seed)).unwrap();
    let msg = b"optrand length";

    let sig = shake128s::sign_with_rng(
        &sk,
        msg,
        &mut FixedRng::new(vec![1u8; <Shake128s as ConstParams>::N]),
        None,
        None,
    )
    .unwrap();
    assert!(shake128s::verify(&pk, msg, &sig, None, None).is_ok());
}

#[test]
fn shake128s_context_and_prehash_are_domain_separated() {
    let seed = vec![0x42u8; <Shake128s>::SEED_BYTES];
    let (pk, sk) = shake128s::keygen_with_rng(&mut FixedRng::new(seed)).unwrap();
    let msg = b"context separated message";
    let optrand = vec![3u8; <Shake128s as ConstParams>::N];

    // Context-based signing/verification
    let sig = shake128s::sign_with_rng(
        &sk,
        msg,
        &mut FixedRng::new(optrand.clone()),
        Some(b"ctx-a"),
        None,
    )
    .unwrap();
    assert!(shake128s::verify(&pk, msg, &sig, Some(b"ctx-a"), None).is_ok());
    assert!(shake128s::verify(&pk, msg, &sig, Some(b"ctx-b"), None).is_err());
    assert!(shake128s::verify(&pk, msg, &sig, None, None).is_err());

    // Pre-hash signing/verification
    let mut ph = [0u8; 64];
    let mut shake = Shake256::default();
    shake.update(msg);
    let mut reader = shake.finalize_xof();
    reader.read(&mut ph);

    let hash_sig = shake128s::sign_with_rng(
        &sk,
        &ph,
        &mut FixedRng::new(optrand.clone()),
        Some(b"ctx-a"),
        Some(HashAlgorithm::Shake256),
    )
    .unwrap();
    assert!(shake128s::verify(
        &pk,
        &ph,
        &hash_sig,
        Some(b"ctx-a"),
        Some(HashAlgorithm::Shake256)
    )
    .is_ok());
    assert!(shake128s::verify(
        &pk,
        &ph,
        &hash_sig,
        Some(b"ctx-b"),
        Some(HashAlgorithm::Shake256)
    )
    .is_err());
}

#[test]
fn shake128s_signing_seed_and_randomness_affect_signature() {
    let seed = vec![0x42u8; <Shake128s>::SEED_BYTES];
    let (pk, sk) = shake128s::keygen_with_rng(&mut FixedRng::new(seed)).unwrap();
    let msg = b"seed sensitivity";

    let sig_a = shake128s::sign_with_rng(
        &sk,
        msg,
        &mut FixedRng::new(vec![1u8; <Shake128s as ConstParams>::N]),
        None,
        None,
    )
    .unwrap();
    let sig_b = shake128s::sign_with_rng(
        &sk,
        msg,
        &mut FixedRng::new(vec![2u8; <Shake128s as ConstParams>::N]),
        None,
        None,
    )
    .unwrap();
    assert_ne!(sig_a.sig, sig_b.sig);
    assert!(shake128s::verify(&pk, msg, &sig_a, None, None).is_ok());
    assert!(shake128s::verify(&pk, msg, &sig_b, None, None).is_ok());

    let random_a = shake128s::sign(&sk, msg, None, None).unwrap();
    let random_b = shake128s::sign(&sk, msg, None, None).unwrap();
    assert_ne!(random_a.sig, random_b.sig);
    assert!(shake128s::verify(&pk, msg, &random_a, None, None).is_ok());
    assert!(shake128s::verify(&pk, msg, &random_b, None, None).is_ok());
}
