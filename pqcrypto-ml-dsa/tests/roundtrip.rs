//! Roundtrip tests for ML-DSA variants.
use pqcrypto_ml_dsa::mldsa44;
use pqcrypto_ml_dsa::mldsa65;
use pqcrypto_ml_dsa::mldsa87;

#[test]
fn test_ml_dsa_44_roundtrip() {
    let seed = [0u8; 32];
    let (pk, sk) = mldsa44::keygen(&seed).unwrap();
    let msg = b"hello world";
    let sig = mldsa44::sign(&sk, msg).unwrap();
    assert!(mldsa44::verify(&pk, msg, &sig));
}

#[test]
fn test_ml_dsa_65_roundtrip() {
    let seed = [0u8; 32];
    let (pk, sk) = mldsa65::keygen(&seed).unwrap();
    let msg = b"hello world";
    let sig = mldsa65::sign(&sk, msg).unwrap();
    assert!(mldsa65::verify(&pk, msg, &sig));
}

#[test]
fn test_ml_dsa_87_roundtrip() {
    let seed = [0u8; 32];
    let (pk, sk) = mldsa87::keygen(&seed).unwrap();
    let msg = b"hello world";
    let sig = mldsa87::sign(&sk, msg).unwrap();
    assert!(mldsa87::verify(&pk, msg, &sig));
}
