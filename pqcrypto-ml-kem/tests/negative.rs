//! ML-KEM (FIPS 203) negative tests.
//!
//! Verifies that decapsulation rejects invalid inputs by producing a
//! different shared secret (implicit rejection per FIPS 203):
//! - Wrong private key (from a different keypair)
//! - Corrupted ciphertext
//! - Zeroed ciphertext
//!
//! Also verifies that basic sanity checks pass (valid roundtrip works).

use pqcrypto_ml_kem::error::Error;
use pqcrypto_ml_kem::mlkem1024;
use pqcrypto_ml_kem::mlkem512;
use pqcrypto_ml_kem::mlkem768;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Sha3_512, Shake256,
};

fn sha3_256_32(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, input);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn shake256_32(input: &[u8]) -> [u8; 32] {
    let mut shake = Shake256::default();
    Update::update(&mut shake, input);
    let mut reader = shake.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

fn sha3_512_64(input: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, input);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

// ─── ML-KEM-512 ───

#[test]
fn mlkem512_negative_wrong_key() {
    let (pk_a, sk_a) = mlkem512::keypair_from_seed(&[0x01u8; 32]).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem512::encaps_deterministic(&pk_a, &msg).unwrap();

    // Verify baseline roundtrip
    let ss_good = mlkem512::decaps(&sk_a, &enc.ciphertext).unwrap();
    assert_eq!(enc.shared_secret, ss_good, "baseline roundtrip failed");

    // Generate a DIFFERENT keypair
    let (_pk_b, sk_b) = mlkem512::keypair_from_seed(&[0x42u8; 32]).unwrap();
    assert_ne!(
        sk_a.as_ref(),
        sk_b.as_ref(),
        "two keygens produced the same sk"
    );

    // Decaps with wrong key should produce DIFFERENT shared secret
    let ss_wrong = mlkem512::decaps(&sk_b, &enc.ciphertext).unwrap();
    assert_ne!(
        ss_wrong, enc.shared_secret,
        "decaps with wrong sk should produce a different shared secret"
    );
}

#[test]
fn mlkem512_negative_corrupted_ct() {
    let (pk, sk) = mlkem512::keypair_from_seed(&[0x01u8; 32]).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem512::encaps_deterministic(&pk, &msg).unwrap();

    // Verify baseline roundtrip
    let ss_good = mlkem512::decaps(&sk, &enc.ciphertext).unwrap();
    assert_eq!(enc.shared_secret, ss_good, "baseline roundtrip failed");

    let mut ct_vec = enc.ciphertext.to_vec();
    for pos in [
        0usize,
        1,
        ct_vec.len() / 3,
        ct_vec.len() / 2,
        ct_vec.len() - 1,
    ] {
        let orig = ct_vec[pos];
        ct_vec[pos] ^= 0xff;
        let ss_bad = mlkem512::decaps(&sk, &ct_vec).unwrap();
        assert_ne!(
            ss_bad, enc.shared_secret,
            "decaps with corrupted ct byte {pos} should produce different shared secret"
        );
        ct_vec[pos] = orig;
    }
}

#[test]
fn mlkem512_negative_zero_ct() {
    let (pk, sk) = mlkem512::keypair_from_seed(&[0x01u8; 32]).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem512::encaps_deterministic(&pk, &msg).unwrap();

    // Verify baseline roundtrip
    let ss_good = mlkem512::decaps(&sk, &enc.ciphertext).unwrap();
    assert_eq!(enc.shared_secret, ss_good, "baseline roundtrip failed");

    let zero_ct = vec![0u8; enc.ciphertext.len()];
    let ss_zero = mlkem512::decaps(&sk, &zero_ct).unwrap();
    assert_ne!(
        ss_zero, enc.shared_secret,
        "decaps with zero ciphertext should produce a different shared secret"
    );
}

#[test]
fn mlkem512_encapsulation_fips_203_shared_secret() {
    let (pk, _sk) = mlkem512::keypair_from_seed(&[0x01u8; 32]).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem512::encaps_deterministic(&pk, &msg).unwrap();

    let h_pk = sha3_256_32(&pk.pk);
    let h_ct = sha3_256_32(&enc.ciphertext);
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&msg);
    g_input[32..].copy_from_slice(&h_pk);
    let g_out = sha3_512_64(&g_input);
    let k_inner = &g_out[..32];

    let mut kdf_input = [0u8; 64];
    kdf_input[..32].copy_from_slice(k_inner);
    kdf_input[32..].copy_from_slice(&h_ct);
    let expected = shake256_32(&kdf_input);

    assert_eq!(enc.shared_secret.as_slice(), &expected[..]);
}

#[test]
fn mlkem512_rejects_invalid_public_key_modulus() {
    let (mut pk, _sk) = mlkem512::keypair_from_seed(&[0x01u8; 32]).unwrap();

    pk.pk[0] = 0xff;
    pk.pk[1] |= 0x0f;

    let err = mlkem512::encaps_deterministic(&pk, &[0xabu8; 32]).unwrap_err();
    assert_eq!(err, Error::InvalidPublicKey);
}

#[test]
fn mlkem512_rejects_corrupted_stored_public_key_hash() {
    let (pk, sk) = mlkem512::keypair_from_seed(&[0x01u8; 32]).unwrap();
    let enc = mlkem512::encaps_deterministic(&pk, &[0xabu8; 32]).unwrap();

    const SK_PK_OFFSET: usize = 2 * 384;
    const PK_SIZE: usize = 800;
    // Build a corrupted SK by mutating the correct-length bytes then re-wrapping
    let mut corrupted = sk.as_ref().to_vec();
    corrupted[SK_PK_OFFSET + PK_SIZE] ^= 0x01;
    let corrupted_sk = mlkem512::SecretKey::from_bytes(&corrupted).unwrap();

    let err = mlkem512::decaps(&corrupted_sk, &enc.ciphertext).unwrap_err();
    assert_eq!(err, Error::InvalidSecretKey);
}

#[test]
fn mlkem512_rejects_oversized_secret_key() {
    let (pk, sk) = mlkem512::keypair_from_seed(&[0x01u8; 32]).unwrap();
    let enc = mlkem512::encaps_deterministic(&pk, &[0xabu8; 32]).unwrap();

    // from_bytes rejects wrong-length inputs
    assert!(mlkem512::SecretKey::from_bytes(&sk.as_ref()[..sk.as_ref().len() / 2]).is_err());
    assert!(mlkem512::SecretKey::from_bytes(&vec![0u8; sk.as_ref().len() + 1]).is_err());
    assert!(mlkem512::SecretKey::from_bytes(&[]).is_err());

    // A valid-length key still works
    mlkem512::decaps(&sk, &enc.ciphertext).expect("valid decaps should succeed");
}

#[test]
fn mlkem512_seed_lengths_must_be_exact() {
    assert_eq!(
        mlkem512::keypair_from_seed(&[0u8; 31]).unwrap_err(),
        Error::InvalidKeyLength
    );
    assert_eq!(
        mlkem512::keypair_from_seed(&[0u8; 33]).unwrap_err(),
        Error::InvalidKeyLength
    );

    let (pk, _sk) = mlkem512::keypair_from_seed(&[0u8; 32]).unwrap();
    assert_eq!(
        mlkem512::encaps_deterministic(&pk, &[0u8; 31]).unwrap_err(),
        Error::InvalidKeyLength
    );
    assert_eq!(
        mlkem512::encaps_deterministic(&pk, &[0u8; 33]).unwrap_err(),
        Error::InvalidKeyLength
    );
}

#[test]
fn mlkem512_corrupted_ciphertext_uses_j_rejection_key() {
    let (pk, sk) = mlkem512::keypair_from_seed(&[0x01u8; 32]).unwrap();
    let enc = mlkem512::encaps_deterministic(&pk, &[0xabu8; 32]).unwrap();
    let mut ct = enc.ciphertext.clone();
    ct[0] ^= 0x01;

    const SK_PK_OFFSET: usize = 2 * 384;
    const PK_SIZE: usize = 800;
    const Z_OFFSET: usize = SK_PK_OFFSET + PK_SIZE + 32;
    let mut rejection_input = Vec::with_capacity(32 + ct.len());
    rejection_input.extend_from_slice(&sk.as_ref()[Z_OFFSET..Z_OFFSET + 32]);
    rejection_input.extend_from_slice(&ct);
    let expected = shake256_32(&rejection_input);

    let ss_bad = mlkem512::decaps(&sk, &ct).unwrap();
    assert_eq!(ss_bad, expected);
    assert_ne!(ss_bad, enc.shared_secret);
}

#[test]
fn decapsulation_rejection_path_does_not_use_slice_equality() {
    let kem_source = include_str!("../src/kem.rs");
    assert!(kem_source.contains("ct.ct_ne(&ct_prime)"));
    assert!(kem_source.contains("u8::conditional_select(&kdf_k[i], &rejection_key[i], fail)"));
    assert!(!kem_source.contains("ct == ct_prime"));
    assert!(!kem_source.contains("ct_prime.as_slice()"));
}

// ─── ML-KEM-768 ───

#[test]
fn mlkem768_negative_wrong_key() {
    let (pk_a, sk_a) = mlkem768::keypair_from_seed(&[0x01u8; 32]).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem768::encaps_deterministic(&pk_a, &msg).unwrap();

    let ss_good = mlkem768::decaps(&sk_a, &enc.ciphertext).unwrap();
    assert_eq!(enc.shared_secret, ss_good, "baseline roundtrip failed");

    let (_pk_b, sk_b) = mlkem768::keypair_from_seed(&[0x42u8; 32]).unwrap();
    assert_ne!(
        sk_a.as_ref(),
        sk_b.as_ref(),
        "two keygens produced the same sk"
    );

    let ss_wrong = mlkem768::decaps(&sk_b, &enc.ciphertext).unwrap();
    assert_ne!(
        ss_wrong, enc.shared_secret,
        "decaps with wrong sk should produce a different shared secret"
    );
}

#[test]
fn mlkem768_negative_corrupted_ct() {
    let (pk, sk) = mlkem768::keypair_from_seed(&[0x01u8; 32]).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem768::encaps_deterministic(&pk, &msg).unwrap();

    let ss_good = mlkem768::decaps(&sk, &enc.ciphertext).unwrap();
    assert_eq!(enc.shared_secret, ss_good, "baseline roundtrip failed");

    let mut ct_vec = enc.ciphertext.to_vec();
    for pos in [
        0usize,
        1,
        ct_vec.len() / 3,
        ct_vec.len() / 2,
        ct_vec.len() - 1,
    ] {
        let orig = ct_vec[pos];
        ct_vec[pos] ^= 0xff;
        let ss_bad = mlkem768::decaps(&sk, &ct_vec).unwrap();
        assert_ne!(
            ss_bad, enc.shared_secret,
            "decaps with corrupted ct byte {pos} should produce different shared secret"
        );
        ct_vec[pos] = orig;
    }
}

#[test]
fn mlkem768_negative_zero_ct() {
    let (pk, sk) = mlkem768::keypair_from_seed(&[0x01u8; 32]).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem768::encaps_deterministic(&pk, &msg).unwrap();

    let ss_good = mlkem768::decaps(&sk, &enc.ciphertext).unwrap();
    assert_eq!(enc.shared_secret, ss_good, "baseline roundtrip failed");

    let zero_ct = vec![0u8; enc.ciphertext.len()];
    let ss_zero = mlkem768::decaps(&sk, &zero_ct).unwrap();
    assert_ne!(
        ss_zero, enc.shared_secret,
        "decaps with zero ciphertext should produce a different shared secret"
    );
}

// ─── ML-KEM-1024 ───

#[test]
fn mlkem1024_negative_wrong_key() {
    let (pk_a, sk_a) = mlkem1024::keypair_from_seed(&[0x01u8; 32]).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem1024::encaps_deterministic(&pk_a, &msg).unwrap();

    let ss_good = mlkem1024::decaps(&sk_a, &enc.ciphertext).unwrap();
    assert_eq!(enc.shared_secret, ss_good, "baseline roundtrip failed");

    let (_pk_b, sk_b) = mlkem1024::keypair_from_seed(&[0x42u8; 32]).unwrap();
    assert_ne!(
        sk_a.as_ref(),
        sk_b.as_ref(),
        "two keygens produced the same sk"
    );

    let ss_wrong = mlkem1024::decaps(&sk_b, &enc.ciphertext).unwrap();
    assert_ne!(
        ss_wrong, enc.shared_secret,
        "decaps with wrong sk should produce a different shared secret"
    );
}

#[test]
fn mlkem1024_negative_corrupted_ct() {
    let (pk, sk) = mlkem1024::keypair_from_seed(&[0x01u8; 32]).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem1024::encaps_deterministic(&pk, &msg).unwrap();

    let ss_good = mlkem1024::decaps(&sk, &enc.ciphertext).unwrap();
    assert_eq!(enc.shared_secret, ss_good, "baseline roundtrip failed");

    let mut ct_vec = enc.ciphertext.to_vec();
    for pos in [
        0usize,
        1,
        ct_vec.len() / 3,
        ct_vec.len() / 2,
        ct_vec.len() - 1,
    ] {
        let orig = ct_vec[pos];
        ct_vec[pos] ^= 0xff;
        let ss_bad = mlkem1024::decaps(&sk, &ct_vec).unwrap();
        assert_ne!(
            ss_bad, enc.shared_secret,
            "decaps with corrupted ct byte {pos} should produce different shared secret"
        );
        ct_vec[pos] = orig;
    }
}

#[test]
fn mlkem1024_negative_zero_ct() {
    let (pk, sk) = mlkem1024::keypair_from_seed(&[0x01u8; 32]).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem1024::encaps_deterministic(&pk, &msg).unwrap();

    let ss_good = mlkem1024::decaps(&sk, &enc.ciphertext).unwrap();
    assert_eq!(enc.shared_secret, ss_good, "baseline roundtrip failed");

    let zero_ct = vec![0u8; enc.ciphertext.len()];
    let ss_zero = mlkem1024::decaps(&sk, &zero_ct).unwrap();
    assert_ne!(
        ss_zero, enc.shared_secret,
        "decaps with zero ciphertext should produce a different shared secret"
    );
}
