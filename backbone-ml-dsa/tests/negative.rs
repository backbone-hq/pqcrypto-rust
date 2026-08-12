//! ML-DSA (FIPS 204) signature negative tests.

use backbone_ml_dsa::mldsa44;
use backbone_ml_dsa::params::{Mldsa44, Params};
use backbone_pqcrypto_internals::kat::FixedRng;

#[test]
fn mldsa44_rejects_malformed_raw_inputs_without_panicking() {
    let (pk, sk) = mldsa44::keygen_with_rng(&mut FixedRng::new(vec![0x42u8; 32])).unwrap();
    let msg = b"malformed raw input";
    let sig =
        mldsa44::sign_with_rng(&sk, msg, &mut FixedRng::new(vec![7u8; 32]), None, None).unwrap();

    assert!(mldsa44::PublicKey::from_bytes(&pk.pk[..pk.pk.len() - 1]).is_err());
    assert!(mldsa44::SecretKey::from_bytes(&sk.as_ref()[..sk.as_ref().len() - 1]).is_err());
    assert!(mldsa44::Signature::from_bytes(&sig.sig[..sig.sig.len() - 1]).is_err());

    let bad_pk = mldsa44::PublicKey { pk: vec![0u8; 1] };
    let bad_sig = mldsa44::Signature { sig: vec![0u8; 1] };

    assert!(mldsa44::verify(&bad_pk, msg, &sig, None, None).is_err());
    assert!(mldsa44::verify(&pk, msg, &bad_sig, None, None).is_err());
    let bad_sk_short = mldsa44::SecretKey::from_bytes(&vec![0u8; 2559]);
    assert!(bad_sk_short.is_err());
}

#[test]
fn mldsa44_rejects_non_canonical_hint_encoding() {
    let (pk, sk) = mldsa44::keygen_with_rng(&mut FixedRng::new(vec![0x42u8; 32])).unwrap();
    let msg = b"non-canonical hint encoding";
    let mut sig =
        mldsa44::sign_with_rng(&sk, msg, &mut FixedRng::new(vec![9u8; 32]), None, None).unwrap();

    let hint_len = <Mldsa44 as Params>::OMEGA + <Mldsa44 as Params>::K;
    let hint_start = sig.sig.len() - hint_len;
    let omega = <Mldsa44 as Params>::OMEGA;
    let final_count = usize::from(sig.sig[hint_start + omega + <Mldsa44 as Params>::K - 1]);
    assert!(
        final_count < omega,
        "test signature unexpectedly used all hints"
    );

    sig.sig[hint_start + final_count] = 1;
    assert!(
        mldsa44::verify(&pk, msg, &sig, None, None).is_err(),
        "verifier must reject non-zero padding in hint encoding"
    );
}

#[test]
fn mldsa44_context_and_prehash_are_domain_separated() {
    let (pk, sk) = mldsa44::keygen_with_rng(&mut FixedRng::new(vec![0x42u8; 32])).unwrap();
    let msg = b"context separated message";
    let rnd = [3u8; 32];

    let sig = mldsa44::sign_with_rng(
        &sk,
        msg,
        &mut FixedRng::new(rnd.to_vec()),
        Some(b"ctx-a"),
        None,
    )
    .unwrap();
    assert!(mldsa44::verify(&pk, msg, &sig, Some(b"ctx-a"), None).is_ok());
    assert!(mldsa44::verify(&pk, msg, &sig, Some(b"ctx-b"), None).is_err());
    assert!(mldsa44::verify(&pk, msg, &sig, None, None).is_err());

    let sig_plain = mldsa44::sign(&sk, msg, None, None).unwrap();
    assert!(mldsa44::verify(&pk, msg, &sig_plain, None, None).is_ok());

    // HashML-DSA with SHAKE-256
    use backbone_ml_dsa::HashAlgorithm;
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;
    let mut ph = [0u8; 64];
    let mut shake = Shake256::default();
    shake.update(msg);
    let mut reader = shake.finalize_xof();
    reader.read(&mut ph);
    let hash_sig = mldsa44::sign_with_rng(
        &sk,
        &ph,
        &mut FixedRng::new(rnd.to_vec()),
        Some(b"ctx-a"),
        Some(HashAlgorithm::Shake256),
    )
    .unwrap();
    assert!(mldsa44::verify(
        &pk,
        &ph,
        &hash_sig,
        Some(b"ctx-a"),
        Some(HashAlgorithm::Shake256)
    )
    .is_ok());
    assert!(mldsa44::verify(
        &pk,
        &ph,
        &hash_sig,
        Some(b"ctx-b"),
        Some(HashAlgorithm::Shake256)
    )
    .is_err());
}

#[test]
fn mldsa44_signing_seed_and_randomness_affect_signature() {
    let (pk, sk) = mldsa44::keygen_with_rng(&mut FixedRng::new(vec![0x42u8; 32])).unwrap();
    let msg = b"seed sensitivity";

    let sig_a =
        mldsa44::sign_with_rng(&sk, msg, &mut FixedRng::new(vec![1u8; 32]), None, None).unwrap();
    let sig_b =
        mldsa44::sign_with_rng(&sk, msg, &mut FixedRng::new(vec![2u8; 32]), None, None).unwrap();
    assert_ne!(sig_a.sig, sig_b.sig);
    assert!(mldsa44::verify(&pk, msg, &sig_a, None, None).is_ok());
    assert!(mldsa44::verify(&pk, msg, &sig_b, None, None).is_ok());

    let random_a = mldsa44::sign(&sk, msg, None, None).unwrap();
    let random_b = mldsa44::sign(&sk, msg, None, None).unwrap();
    assert_ne!(random_a.sig, random_b.sig);
    assert!(mldsa44::verify(&pk, msg, &random_a, None, None).is_ok());
    assert!(mldsa44::verify(&pk, msg, &random_b, None, None).is_ok());
}
