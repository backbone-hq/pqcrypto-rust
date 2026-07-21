//! Public HQC KEM roundtrip tests.

use backbone_hqc::{hqc128, hqc192, hqc256};

#[test]
fn hqc1_public_roundtrip() {
    let (pk, sk) = hqc128::keypair_from_seed(b"0123456789abcdef0123456789abcdef").expect("keygen");
    let enc = hqc128::encaps(&pk).expect("encaps");
    let dec = hqc128::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn hqc3_public_roundtrip() {
    let (pk, sk) = hqc192::keypair_from_seed(b"0123456789abcdef0123456789abcdef").expect("keygen");
    let enc = hqc192::encaps(&pk).expect("encaps");
    let dec = hqc192::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn hqc5_public_roundtrip() {
    let (pk, sk) = hqc256::keypair_from_seed(b"0123456789abcdef0123456789abcdef").expect("keygen");
    let enc = hqc256::encaps(&pk).expect("encaps");
    let dec = hqc256::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}
