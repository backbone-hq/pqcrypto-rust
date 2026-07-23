//! ML-DSA (FIPS 204) signature negative tests.

use backbone_ml_dsa::mldsa44;
use backbone_ml_dsa::mldsa65;
use backbone_ml_dsa::mldsa87;
use backbone_ml_dsa::params::{Mldsa44, Params};

#[test]
fn mldsa44_negative_message() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa44::keygen(&seed).unwrap();
    let msg = b"hello ml-dsa negative test";
    let sig = mldsa44::sign(&sk, msg).unwrap();
    assert!(mldsa44::verify(&pk, msg, &sig));
    let mut bad_msg = msg.to_vec();
    bad_msg[0] ^= 0xff;
    assert!(
        !mldsa44::verify(&pk, &bad_msg, &sig),
        "verify should reject corrupted message"
    );
}

#[test]
fn mldsa44_negative_wrong_key() {
    let seed_a = [0x42u8; 32];
    let seed_b = [0xabu8; 32];
    let msg = b"hello ml-dsa wrong-key test";
    let (pk_a, sk_a) = mldsa44::keygen(&seed_a).unwrap();
    let (pk_b, _) = mldsa44::keygen(&seed_b).unwrap();
    let sig = mldsa44::sign(&sk_a, msg).unwrap();
    assert!(mldsa44::verify(&pk_a, msg, &sig));
    assert!(
        !mldsa44::verify(&pk_b, msg, &sig),
        "verify should reject wrong public key"
    );
}

#[test]
fn mldsa44_negative_corrupted_sig() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa44::keygen(&seed).unwrap();
    let msg = b"hello ml-dsa negative test";
    let sig = mldsa44::sign(&sk, msg).unwrap();
    assert!(mldsa44::verify(&pk, msg, &sig));
    let corrupt_pos = 40usize;
    if corrupt_pos < sig.sig.len() {
        let mut bad_bytes = sig.sig.clone();
        bad_bytes[corrupt_pos] ^= 0x01;
        let bad_sig = mldsa44::Signature { sig: bad_bytes };
        assert!(
            !mldsa44::verify(&pk, msg, &bad_sig),
            "verify should reject corrupted sig"
        );
    }
}

#[test]
fn mldsa44_negative_truncated_sig() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa44::keygen(&seed).unwrap();
    let msg = b"hello ml-dsa negative test";
    let sig = mldsa44::sign(&sk, msg).unwrap();
    assert!(mldsa44::verify(&pk, msg, &sig));
    let empty_sig = mldsa44::Signature { sig: vec![] };
    assert!(
        !mldsa44::verify(&pk, msg, &empty_sig),
        "verify should reject empty sig"
    );
    let half_bytes = sig.sig[..sig.sig.len() / 2].to_vec();
    let half_sig = mldsa44::Signature { sig: half_bytes };
    assert!(
        !mldsa44::verify(&pk, msg, &half_sig),
        "verify should reject truncated sig"
    );
}

#[test]
fn mldsa44_negative_empty_msg() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa44::keygen(&seed).unwrap();
    let msg = b"";
    let sig = mldsa44::sign(&sk, msg).unwrap();
    assert!(
        mldsa44::verify(&pk, msg, &sig),
        "empty message should verify"
    );
}

#[test]
fn mldsa65_negative_message() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa65::keygen(&seed).unwrap();
    let msg = b"hello ml-dsa negative test";
    let sig = mldsa65::sign(&sk, msg).unwrap();
    assert!(mldsa65::verify(&pk, msg, &sig));
    let mut bad_msg = msg.to_vec();
    bad_msg[0] ^= 0xff;
    assert!(
        !mldsa65::verify(&pk, &bad_msg, &sig),
        "verify should reject corrupted message"
    );
}

#[test]
fn mldsa65_negative_wrong_key() {
    let seed_a = [0x42u8; 32];
    let seed_b = [0xabu8; 32];
    let msg = b"hello ml-dsa wrong-key test";
    let (pk_a, sk_a) = mldsa65::keygen(&seed_a).unwrap();
    let (pk_b, _) = mldsa65::keygen(&seed_b).unwrap();
    let sig = mldsa65::sign(&sk_a, msg).unwrap();
    assert!(mldsa65::verify(&pk_a, msg, &sig));
    assert!(
        !mldsa65::verify(&pk_b, msg, &sig),
        "verify should reject wrong public key"
    );
}

#[test]
fn mldsa65_negative_corrupted_sig() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa65::keygen(&seed).unwrap();
    let msg = b"hello ml-dsa negative test";
    let sig = mldsa65::sign(&sk, msg).unwrap();
    assert!(mldsa65::verify(&pk, msg, &sig));
    let corrupt_pos = 40usize;
    if corrupt_pos < sig.sig.len() {
        let mut bad_bytes = sig.sig.clone();
        bad_bytes[corrupt_pos] ^= 0x01;
        let bad_sig = mldsa65::Signature { sig: bad_bytes };
        assert!(
            !mldsa65::verify(&pk, msg, &bad_sig),
            "verify should reject corrupted sig"
        );
    }
}

#[test]
fn mldsa65_negative_truncated_sig() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa65::keygen(&seed).unwrap();
    let msg = b"hello ml-dsa negative test";
    let sig = mldsa65::sign(&sk, msg).unwrap();
    assert!(mldsa65::verify(&pk, msg, &sig));
    let empty_sig = mldsa65::Signature { sig: vec![] };
    assert!(
        !mldsa65::verify(&pk, msg, &empty_sig),
        "verify should reject empty sig"
    );
    let half_bytes = sig.sig[..sig.sig.len() / 2].to_vec();
    let half_sig = mldsa65::Signature { sig: half_bytes };
    assert!(
        !mldsa65::verify(&pk, msg, &half_sig),
        "verify should reject truncated sig"
    );
}

#[test]
fn mldsa65_negative_empty_msg() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa65::keygen(&seed).unwrap();
    let msg = b"";
    let sig = mldsa65::sign(&sk, msg).unwrap();
    assert!(
        mldsa65::verify(&pk, msg, &sig),
        "empty message should verify"
    );
}

#[test]
fn mldsa87_negative_message() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa87::keygen(&seed).unwrap();
    let msg = b"hello ml-dsa negative test";
    let sig = mldsa87::sign(&sk, msg).unwrap();
    assert!(mldsa87::verify(&pk, msg, &sig));
    let mut bad_msg = msg.to_vec();
    bad_msg[0] ^= 0xff;
    assert!(
        !mldsa87::verify(&pk, &bad_msg, &sig),
        "verify should reject corrupted message"
    );
}

#[test]
fn mldsa87_negative_wrong_key() {
    let seed_a = [0x42u8; 32];
    let seed_b = [0xabu8; 32];
    let msg = b"hello ml-dsa wrong-key test";
    let (pk_a, sk_a) = mldsa87::keygen(&seed_a).unwrap();
    let (pk_b, _) = mldsa87::keygen(&seed_b).unwrap();
    let sig = mldsa87::sign(&sk_a, msg).unwrap();
    assert!(mldsa87::verify(&pk_a, msg, &sig));
    assert!(
        !mldsa87::verify(&pk_b, msg, &sig),
        "verify should reject wrong public key"
    );
}

#[test]
fn mldsa87_negative_corrupted_sig() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa87::keygen(&seed).unwrap();
    let msg = b"hello ml-dsa negative test";
    let sig = mldsa87::sign(&sk, msg).unwrap();
    assert!(mldsa87::verify(&pk, msg, &sig));
    let corrupt_pos = 40usize;
    if corrupt_pos < sig.sig.len() {
        let mut bad_bytes = sig.sig.clone();
        bad_bytes[corrupt_pos] ^= 0x01;
        let bad_sig = mldsa87::Signature { sig: bad_bytes };
        assert!(
            !mldsa87::verify(&pk, msg, &bad_sig),
            "verify should reject corrupted sig"
        );
    }
}

#[test]
fn mldsa87_negative_truncated_sig() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa87::keygen(&seed).unwrap();
    let msg = b"hello ml-dsa negative test";
    let sig = mldsa87::sign(&sk, msg).unwrap();
    assert!(mldsa87::verify(&pk, msg, &sig));
    let empty_sig = mldsa87::Signature { sig: vec![] };
    assert!(
        !mldsa87::verify(&pk, msg, &empty_sig),
        "verify should reject empty sig"
    );
    let half_bytes = sig.sig[..sig.sig.len() / 2].to_vec();
    let half_sig = mldsa87::Signature { sig: half_bytes };
    assert!(
        !mldsa87::verify(&pk, msg, &half_sig),
        "verify should reject truncated sig"
    );
}

#[test]
fn mldsa87_negative_empty_msg() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa87::keygen(&seed).unwrap();
    let msg = b"";
    let sig = mldsa87::sign(&sk, msg).unwrap();
    assert!(
        mldsa87::verify(&pk, msg, &sig),
        "empty message should verify"
    );
}

#[test]
fn mldsa44_rejects_malformed_raw_inputs_without_panicking() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa44::keygen(&seed).unwrap();
    let msg = b"malformed raw input";
    let sig = mldsa44::sign_deterministic(&sk, msg, &[7u8; 32]).unwrap();

    assert!(mldsa44::PublicKey::from_bytes(&pk.pk[..pk.pk.len() - 1]).is_err());
    assert!(mldsa44::SecretKey::from_bytes(&sk.as_ref()[..sk.as_ref().len() - 1]).is_err());
    assert!(mldsa44::Signature::from_bytes(&sig.sig[..sig.sig.len() - 1]).is_err());
    assert!(mldsa44::keygen_checked(&[0u8; 31]).is_err());
    assert!(mldsa44::sign_deterministic(&sk, msg, &[0u8; 31]).is_err());

    let bad_pk = mldsa44::PublicKey { pk: vec![0u8; 1] };
    let bad_sig = mldsa44::Signature { sig: vec![0u8; 1] };

    assert!(!mldsa44::verify(&bad_pk, msg, &sig));
    assert!(mldsa44::verify_result(&bad_pk, msg, &sig).is_err());
    assert!(mldsa44::verify_result(&pk, msg, &bad_sig).is_err());
    let bad_sk_short = mldsa44::SecretKey::from_bytes(&vec![0u8; 2559]);
    assert!(bad_sk_short.is_err());
}

#[test]
fn mldsa44_rejects_non_canonical_hint_encoding() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa44::keygen(&seed).unwrap();
    let msg = b"non-canonical hint encoding";
    let mut sig = mldsa44::sign_deterministic(&sk, msg, &[9u8; 32]).unwrap();

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
        !mldsa44::verify(&pk, msg, &sig),
        "verifier must reject non-zero padding in hint encoding"
    );
}

#[test]
fn mldsa44_context_and_prehash_are_domain_separated() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa44::keygen(&seed).unwrap();
    let msg = b"context separated message";
    let rnd = [3u8; 32];

    let sig = mldsa44::sign_deterministic_with_context(&sk, msg, b"ctx-a", &rnd).unwrap();
    assert!(mldsa44::verify_with_context(&pk, msg, &sig, b"ctx-a"));
    assert!(!mldsa44::verify_with_context(&pk, msg, &sig, b"ctx-b"));
    assert!(!mldsa44::verify(&pk, msg, &sig));

    let hash_sig = mldsa44::sign_prehashed_shake256_with_context(&sk, msg, b"ctx-a", &rnd).unwrap();
    assert!(mldsa44::verify_prehashed_shake256_with_context(
        &pk, msg, &hash_sig, b"ctx-a"
    ));
    assert!(!mldsa44::verify_prehashed_shake256_with_context(
        &pk, msg, &hash_sig, b"ctx-b"
    ));
}

#[test]
fn mldsa44_signing_seed_and_randomness_affect_signature() {
    let seed = [0x42u8; 32];
    let (pk, sk) = mldsa44::keygen(&seed).unwrap();
    let msg = b"seed sensitivity";

    let sig_a = mldsa44::sign_deterministic(&sk, msg, &[1u8; 32]).unwrap();
    let sig_b = mldsa44::sign_deterministic(&sk, msg, &[2u8; 32]).unwrap();
    assert_ne!(sig_a.sig, sig_b.sig);
    assert!(mldsa44::verify(&pk, msg, &sig_a));
    assert!(mldsa44::verify(&pk, msg, &sig_b));

    let random_a = mldsa44::sign(&sk, msg).unwrap();
    let random_b = mldsa44::sign(&sk, msg).unwrap();
    assert_ne!(random_a.sig, random_b.sig);
    assert!(mldsa44::verify(&pk, msg, &random_a));
    assert!(mldsa44::verify(&pk, msg, &random_b));
}
