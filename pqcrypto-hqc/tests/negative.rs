//! HQC (FIPS 209) negative tests.
//!
//! Verifies decapsulation behavior for invalid inputs:
//! - Wrong secret key (from a different keypair) returns a fallback secret
//! - Corrupted ciphertext returns a fallback secret
//! - Invalid-length inputs
//!
//! Uses the public per-variant API: keypair_from_seed, encaps, decaps.

use pqcrypto_hqc::{hqc128, hqc192, hqc256};

// ─── HQC-1 ───

fn make_hqc128(seed: &[u8]) -> (hqc128::PublicKey, hqc128::SecretKey, Vec<u8>, [u8; 32]) {
    let (pk, sk) = hqc128::keypair_from_seed(seed).expect("test keygen");
    let enc = hqc128::encaps(&pk).expect("test encaps");
    (pk, sk, enc.ciphertext, enc.shared_secret)
}

#[test]
fn hqc128_negative_wrong_key() {
    let (_pk_a, sk_a, ct, ss) = make_hqc128(b"0123456789abcdef0123456789abcdef");
    let (_pk_b, sk_b, _ct_b, _ss_b) = make_hqc128(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab");
    assert_ne!(
        sk_a.as_ref(),
        sk_b.as_ref(),
        "two keygens produced the same sk"
    );
    let result = hqc128::decaps(&sk_b, &ct).expect("wrong-key decaps returns fallback");
    assert_ne!(
        result, ss,
        "wrong-key decaps should produce fallback secret"
    );
}

#[test]
fn hqc128_negative_corrupted_ct() {
    let (_pk, sk, mut ct, ss) = make_hqc128(b"9876543210abcdef9876543210abcdef");
    for pos in [0usize, 1, ct.len() / 3, ct.len() / 2, ct.len() - 1] {
        let orig = ct[pos];
        ct[pos] ^= 0xff;
        let result = hqc128::decaps(&sk, &ct).expect("corrupted-ct decaps returns fallback");
        assert_ne!(
            result, ss,
            "decaps with corrupted ct byte {pos} should produce fallback secret"
        );
        ct[pos] = orig;
    }
}

#[test]
fn hqc128_negative_invalid_ct_len() {
    let (_pk, sk, ct, _ss) = make_hqc128(b"aabbccdd11223344aabbccdd11223344");
    assert!(
        hqc128::decaps(&sk, &[]).is_err(),
        "decaps with empty ct should fail"
    );
    assert!(
        hqc128::decaps(&sk, &ct[..ct.len() / 2]).is_err(),
        "decaps with truncated ct should fail"
    );
}

#[test]
fn hqc128_negative_invalid_sk_len() {
    // SecretKey::from_bytes rejects wrong-length inputs
    assert!(
        hqc128::SecretKey::from_bytes(&[]).is_err(),
        "from_bytes with empty data should fail"
    );
    assert!(
        hqc128::SecretKey::from_bytes(&[0u8; 1]).is_err(),
        "from_bytes with too-short data should fail"
    );
    // A properly constructed key works
    let (pk, sk) =
        hqc128::keypair_from_seed(b"0123456789abcdef0123456789abcdef").expect("test keygen");
    let enc = hqc128::encaps(&pk).expect("test encaps");
    let ss = hqc128::decaps(&sk, &enc.ciphertext).expect("valid decaps");
    assert_eq!(enc.shared_secret, ss);
}

// ─── HQC-3 ───

fn make_hqc192(seed: &[u8]) -> (hqc192::PublicKey, hqc192::SecretKey, Vec<u8>, [u8; 32]) {
    let (pk, sk) = hqc192::keypair_from_seed(seed).expect("test keygen");
    let enc = hqc192::encaps(&pk).expect("test encaps");
    (pk, sk, enc.ciphertext, enc.shared_secret)
}

#[test]
fn hqc192_negative_wrong_key() {
    let (_pk_a, sk_a, ct, ss) = make_hqc192(b"abcdef1234567890abcdef1234567890");
    let (_pk_b, sk_b, _ct_b, _ss_b) = make_hqc192(b"fedcba0987654321fedcba0987654321");
    assert_ne!(
        sk_a.as_ref(),
        sk_b.as_ref(),
        "two keygens produced the same sk"
    );
    let result = hqc192::decaps(&sk_b, &ct).expect("wrong-key decaps returns fallback");
    assert_ne!(
        result, ss,
        "wrong-key decaps should produce fallback secret"
    );
}

#[test]
fn hqc192_negative_corrupted_ct() {
    let (_pk, sk, mut ct, ss) = make_hqc192(b"11223344556677881122334455667788");
    for pos in [0usize, 1, ct.len() / 3, ct.len() / 2, ct.len() - 1] {
        let orig = ct[pos];
        ct[pos] ^= 0xff;
        let result = hqc192::decaps(&sk, &ct).expect("corrupted-ct decaps returns fallback");
        assert_ne!(
            result, ss,
            "decaps with corrupted ct byte {pos} should produce fallback secret"
        );
        ct[pos] = orig;
    }
}

#[test]
fn hqc192_negative_invalid_ct_len() {
    let (_pk, sk, ct, _ss) = make_hqc192(b"aabbccdd00112233aabbccdd00112233");
    assert!(
        hqc192::decaps(&sk, &[]).is_err(),
        "decaps with empty ct should fail"
    );
    assert!(
        hqc192::decaps(&sk, &ct[..ct.len() / 2]).is_err(),
        "decaps with truncated ct should fail"
    );
}

#[test]
fn hqc192_negative_invalid_sk_len() {
    // SecretKey::from_bytes rejects wrong-length inputs
    assert!(
        hqc192::SecretKey::from_bytes(&[]).is_err(),
        "from_bytes with empty data should fail"
    );
    assert!(
        hqc192::SecretKey::from_bytes(&[0u8; 1]).is_err(),
        "from_bytes with too-short data should fail"
    );
    // A properly constructed key works
    let (pk, sk) =
        hqc192::keypair_from_seed(b"0123456789abcdef0123456789abcdef").expect("test keygen");
    let enc = hqc192::encaps(&pk).expect("test encaps");
    let ss = hqc192::decaps(&sk, &enc.ciphertext).expect("valid decaps");
    assert_eq!(enc.shared_secret, ss);
}

// ─── HQC-5 ───

fn make_hqc256(seed: &[u8]) -> (hqc256::PublicKey, hqc256::SecretKey, Vec<u8>, [u8; 32]) {
    let (pk, sk) = hqc256::keypair_from_seed(seed).expect("test keygen");
    let enc = hqc256::encaps(&pk).expect("test encaps");
    (pk, sk, enc.ciphertext, enc.shared_secret)
}

#[test]
fn hqc256_negative_wrong_key() {
    let (_pk_a, sk_a, ct, ss) = make_hqc256(b"deadbeefcafebabedeadbeefcafebabe");
    let (_pk_b, sk_b, _ct_b, _ss_b) = make_hqc256(b"baadf00dbaadf00dbaadf00dbaadf00d");
    assert_ne!(
        sk_a.as_ref(),
        sk_b.as_ref(),
        "two keygens produced the same sk"
    );
    let result = hqc256::decaps(&sk_b, &ct).expect("wrong-key decaps returns fallback");
    assert_ne!(
        result, ss,
        "wrong-key decaps should produce fallback secret"
    );
}

#[test]
fn hqc256_negative_corrupted_ct() {
    let (_pk, sk, mut ct, ss) = make_hqc256(b"99887766554433229988776655443322");
    for pos in [0usize, 1, ct.len() / 3, ct.len() / 2, ct.len() - 1] {
        let orig = ct[pos];
        ct[pos] ^= 0xff;
        let result = hqc256::decaps(&sk, &ct).expect("corrupted-ct decaps returns fallback");
        assert_ne!(
            result, ss,
            "decaps with corrupted ct byte {pos} should produce fallback secret"
        );
        ct[pos] = orig;
    }
}

#[test]
fn hqc256_negative_invalid_ct_len() {
    let (_pk, sk, ct, _ss) = make_hqc256(b"12345678abcdefab12345678abcdefab");
    assert!(
        hqc256::decaps(&sk, &[]).is_err(),
        "decaps with empty ct should fail"
    );
    assert!(
        hqc256::decaps(&sk, &ct[..ct.len() / 2]).is_err(),
        "decaps with truncated ct should fail"
    );
}

#[test]
fn hqc256_negative_invalid_sk_len() {
    // SecretKey::from_bytes rejects wrong-length inputs
    assert!(
        hqc256::SecretKey::from_bytes(&[]).is_err(),
        "from_bytes with empty data should fail"
    );
    assert!(
        hqc256::SecretKey::from_bytes(&[0u8; 1]).is_err(),
        "from_bytes with too-short data should fail"
    );
    // A properly constructed key works
    let (pk, sk) =
        hqc256::keypair_from_seed(b"0123456789abcdef0123456789abcdef").expect("test keygen");
    let enc = hqc256::encaps(&pk).expect("test encaps");
    let ss = hqc256::decaps(&sk, &enc.ciphertext).expect("valid decaps");
    assert_eq!(enc.shared_secret, ss);
}
