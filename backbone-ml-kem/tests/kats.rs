//! ML-KEM (FIPS 203) roundtrip & determinism tests.
//! Uses the public per-variant API.

use backbone_ml_kem::mlkem1024;
use backbone_ml_kem::mlkem512;
use backbone_ml_kem::mlkem768;

#[test]
fn test_512_roundtrip() {
    let seed = [0x01u8; 32];
    let (pk, sk) = mlkem512::keypair_from_seed(&seed).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem512::encaps_deterministic(&pk, &msg).unwrap();
    let ss2 = mlkem512::decaps(&sk, &enc.ciphertext).unwrap();
    assert_eq!(enc.shared_secret, ss2, "roundtrip failed for ML-KEM-512");
}

#[test]
fn test_768_roundtrip() {
    let seed = [0x01u8; 32];
    let (pk, sk) = mlkem768::keypair_from_seed(&seed).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem768::encaps_deterministic(&pk, &msg).unwrap();
    let ss2 = mlkem768::decaps(&sk, &enc.ciphertext).unwrap();
    assert_eq!(enc.shared_secret, ss2, "roundtrip failed for ML-KEM-768");
}

#[test]
fn test_1024_roundtrip() {
    let seed = [0x01u8; 32];
    let (pk, sk) = mlkem1024::keypair_from_seed(&seed).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem1024::encaps_deterministic(&pk, &msg).unwrap();
    let ss2 = mlkem1024::decaps(&sk, &enc.ciphertext).unwrap();
    assert_eq!(enc.shared_secret, ss2, "roundtrip failed for ML-KEM-1024");
}

#[test]
fn test_512_deterministic() {
    let seed = [0x01u8; 32];
    let (pk1, sk1) = mlkem512::keypair_from_seed(&seed).unwrap();
    let (pk2, sk2) = mlkem512::keypair_from_seed(&seed).unwrap();
    assert_eq!(pk1.pk, pk2.pk, "ek not deterministic");
    assert_eq!(sk1.as_ref(), sk2.as_ref(), "dk not deterministic");
    assert!(pk1.pk.iter().any(|&b| b != 0), "pk is all zeros");
}

#[test]
fn test_768_deterministic() {
    let seed = [0x01u8; 32];
    let (pk1, sk1) = mlkem768::keypair_from_seed(&seed).unwrap();
    let (pk2, sk2) = mlkem768::keypair_from_seed(&seed).unwrap();
    assert_eq!(pk1.pk, pk2.pk, "ek not deterministic");
    assert_eq!(sk1.as_ref(), sk2.as_ref(), "dk not deterministic");
    assert!(pk1.pk.iter().any(|&b| b != 0), "pk is all zeros");
}

#[test]
fn test_1024_deterministic() {
    let seed = [0x01u8; 32];
    let (pk1, sk1) = mlkem1024::keypair_from_seed(&seed).unwrap();
    let (pk2, sk2) = mlkem1024::keypair_from_seed(&seed).unwrap();
    assert_eq!(pk1.pk, pk2.pk, "ek not deterministic");
    assert_eq!(sk1.as_ref(), sk2.as_ref(), "dk not deterministic");
    assert!(pk1.pk.iter().any(|&b| b != 0), "pk is all zeros");
}
