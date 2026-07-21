//! Streamlined NTRU Prime negative tests.
//!
//! Verifies decapsulation behavior for invalid inputs:
//! - Wrong secret key (from a different keypair) returns a different shared secret
//! - Corrupted ciphertext returns a different shared secret
//! - Invalid-length ciphertext is rejected
//! - Invalid-length secret key is rejected

use backbone_sntrup::error::Error;
use backbone_sntrup::{sntrup653, sntrup761, sntrup857};

// ─── SNTRUP-653 ────────────────────────────────────────────────────────────

#[test]
fn sntrup653_negative_wrong_key() {
    let (pk_a, _sk_a) = sntrup653::keypair_from_seed(&[0x42u8; 32]).expect("keygen A");
    let (_pk_b, sk_b) = sntrup653::keypair_from_seed(&[0x99u8; 32]).expect("keygen B");
    let enc = sntrup653::encaps_deterministic(&pk_a, &[0x13u8; 32]).expect("encaps should succeed");

    let wrong_key_ss = sntrup653::decaps(&sk_b, &enc.ciphertext).expect("decaps should succeed");
    assert_ne!(wrong_key_ss, enc.shared_secret);
}

#[test]
fn sntrup653_negative_corrupted_ct() {
    let (pk, _sk_a) = sntrup653::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let sk = sntrup653::SecretKey::from_bytes(_sk_a.as_ref()).unwrap();
    let enc = sntrup653::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps should succeed");

    for pos in [
        0usize,
        1,
        enc.ciphertext.len() / 3,
        enc.ciphertext.len() / 2,
        enc.ciphertext.len() - 1,
    ] {
        let mut ct = enc.ciphertext.clone();
        ct[pos] ^= 0xff;
        let tampered_ss =
            sntrup653::decaps(&sk, &ct).expect("same-length tampered ciphertext uses fallback");
        assert_ne!(tampered_ss, enc.shared_secret, "tampered byte {pos}");
    }
}

#[test]
fn sntrup653_negative_invalid_ct_len() {
    let (pk, sk) = sntrup653::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = sntrup653::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps should succeed");

    assert_eq!(
        sntrup653::decaps(&sk, &[]).expect_err("empty ct"),
        Error::InvalidCiphertextLength
    );
    assert_eq!(
        sntrup653::decaps(&sk, &enc.ciphertext[..enc.ciphertext.len() - 1])
            .expect_err("truncated ct"),
        Error::InvalidCiphertextLength
    );
    assert_eq!(
        sntrup653::decaps(&sk, &[enc.ciphertext.as_slice(), &[0u8]].concat())
            .expect_err("oversized ct"),
        Error::InvalidCiphertextLength
    );
}

#[test]
fn sntrup653_negative_invalid_sk_len() {
    assert!(sntrup653::SecretKey::from_bytes(&[]).is_err());
    assert!(sntrup653::SecretKey::from_bytes(&[0u8; 1]).is_err());

    // A properly constructed key still works
    let (pk, sk) = sntrup653::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = sntrup653::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let ss = sntrup653::decaps(&sk, &enc.ciphertext).expect("valid decaps");
    assert_eq!(enc.shared_secret, ss);
}

// ─── SNTRUP-761 ────────────────────────────────────────────────────────────

#[test]
fn sntrup761_negative_wrong_key() {
    let (pk_a, _sk_a) = sntrup761::keypair_from_seed(&[0x42u8; 32]).expect("keygen A");
    let (_pk_b, sk_b) = sntrup761::keypair_from_seed(&[0x99u8; 32]).expect("keygen B");
    let enc = sntrup761::encaps_deterministic(&pk_a, &[0x13u8; 32]).expect("encaps should succeed");

    let wrong_key_ss = sntrup761::decaps(&sk_b, &enc.ciphertext).expect("decaps should succeed");
    assert_ne!(wrong_key_ss, enc.shared_secret);
}

#[test]
fn sntrup761_negative_corrupted_ct() {
    let (pk, _sk_a) = sntrup761::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let sk = sntrup761::SecretKey::from_bytes(_sk_a.as_ref()).unwrap();
    let enc = sntrup761::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps should succeed");

    for pos in [
        0usize,
        1,
        enc.ciphertext.len() / 3,
        enc.ciphertext.len() / 2,
        enc.ciphertext.len() - 1,
    ] {
        let mut ct = enc.ciphertext.clone();
        ct[pos] ^= 0xff;
        let tampered_ss =
            sntrup761::decaps(&sk, &ct).expect("same-length tampered ciphertext uses fallback");
        assert_ne!(tampered_ss, enc.shared_secret, "tampered byte {pos}");
    }
}

#[test]
fn sntrup761_negative_invalid_ct_len() {
    let (pk, sk) = sntrup761::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = sntrup761::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps should succeed");

    assert_eq!(
        sntrup761::decaps(&sk, &[]).expect_err("empty ct"),
        Error::InvalidCiphertextLength
    );
    assert_eq!(
        sntrup761::decaps(&sk, &enc.ciphertext[..enc.ciphertext.len() - 1])
            .expect_err("truncated ct"),
        Error::InvalidCiphertextLength
    );
    assert_eq!(
        sntrup761::decaps(&sk, &[enc.ciphertext.as_slice(), &[0u8]].concat())
            .expect_err("oversized ct"),
        Error::InvalidCiphertextLength
    );
}

#[test]
fn sntrup761_negative_invalid_sk_len() {
    assert!(sntrup761::SecretKey::from_bytes(&[]).is_err());
    assert!(sntrup761::SecretKey::from_bytes(&[0u8; 1]).is_err());

    // A properly constructed key still works
    let (pk, sk) = sntrup761::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = sntrup761::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let ss = sntrup761::decaps(&sk, &enc.ciphertext).expect("valid decaps");
    assert_eq!(enc.shared_secret, ss);
}

// ─── SNTRUP-857 ────────────────────────────────────────────────────────────

#[test]
fn sntrup857_negative_wrong_key() {
    let (pk_a, _sk_a) = sntrup857::keypair_from_seed(&[0x42u8; 32]).expect("keygen A");
    let (_pk_b, sk_b) = sntrup857::keypair_from_seed(&[0x99u8; 32]).expect("keygen B");
    let enc = sntrup857::encaps_deterministic(&pk_a, &[0x13u8; 32]).expect("encaps should succeed");

    let wrong_key_ss = sntrup857::decaps(&sk_b, &enc.ciphertext).expect("decaps should succeed");
    assert_ne!(wrong_key_ss, enc.shared_secret);
}

#[test]
fn sntrup857_negative_corrupted_ct() {
    let (pk, _sk_a) = sntrup857::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let sk = sntrup857::SecretKey::from_bytes(_sk_a.as_ref()).unwrap();
    let enc = sntrup857::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps should succeed");

    for pos in [
        0usize,
        1,
        enc.ciphertext.len() / 3,
        enc.ciphertext.len() / 2,
        enc.ciphertext.len() - 1,
    ] {
        let mut ct = enc.ciphertext.clone();
        ct[pos] ^= 0xff;
        let tampered_ss =
            sntrup857::decaps(&sk, &ct).expect("same-length tampered ciphertext uses fallback");
        assert_ne!(tampered_ss, enc.shared_secret, "tampered byte {pos}");
    }
}

#[test]
fn sntrup857_negative_invalid_ct_len() {
    let (pk, sk) = sntrup857::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = sntrup857::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps should succeed");

    assert_eq!(
        sntrup857::decaps(&sk, &[]).expect_err("empty ct"),
        Error::InvalidCiphertextLength
    );
    assert_eq!(
        sntrup857::decaps(&sk, &enc.ciphertext[..enc.ciphertext.len() - 1])
            .expect_err("truncated ct"),
        Error::InvalidCiphertextLength
    );
    assert_eq!(
        sntrup857::decaps(&sk, &[enc.ciphertext.as_slice(), &[0u8]].concat())
            .expect_err("oversized ct"),
        Error::InvalidCiphertextLength
    );
}

#[test]
fn sntrup857_negative_invalid_sk_len() {
    assert!(sntrup857::SecretKey::from_bytes(&[]).is_err());
    assert!(sntrup857::SecretKey::from_bytes(&[0u8; 1]).is_err());

    // A properly constructed key still works
    let (pk, sk) = sntrup857::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = sntrup857::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let ss = sntrup857::decaps(&sk, &enc.ciphertext).expect("valid decaps");
    assert_eq!(enc.shared_secret, ss);
}
