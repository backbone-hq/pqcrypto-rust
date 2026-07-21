//! Public Classic McEliece roundtrip tests using deterministic key generation and encapsulation.

use backbone_mceliece::{
    mceliece348864, mceliece348864f, mceliece460896, mceliece460896f, mceliece6688128,
    mceliece6688128f, mceliece6960119, mceliece6960119f, mceliece8192128, mceliece8192128f,
};

#[test]
fn mceliece348864_roundtrip() {
    let (pk, sk) = mceliece348864::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = mceliece348864::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = mceliece348864::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece348864f_roundtrip() {
    let (pk, sk) = mceliece348864f::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = mceliece348864f::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = mceliece348864f::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece460896_roundtrip() {
    let (pk, sk) = mceliece460896::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = mceliece460896::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = mceliece460896::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece460896f_roundtrip() {
    let (pk, sk) = mceliece460896f::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = mceliece460896f::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = mceliece460896f::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece6688128_roundtrip() {
    let (pk, sk) = mceliece6688128::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = mceliece6688128::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = mceliece6688128::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece6688128f_roundtrip() {
    let (pk, sk) = mceliece6688128f::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = mceliece6688128f::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = mceliece6688128f::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece6960119_roundtrip() {
    let (pk, sk) = mceliece6960119::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = mceliece6960119::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = mceliece6960119::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece6960119f_roundtrip() {
    let (pk, sk) = mceliece6960119f::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = mceliece6960119f::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = mceliece6960119f::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece8192128_roundtrip() {
    let (pk, sk) = mceliece8192128::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = mceliece8192128::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = mceliece8192128::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mceliece8192128f_roundtrip() {
    let (pk, sk) = mceliece8192128f::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = mceliece8192128f::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = mceliece8192128f::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}
