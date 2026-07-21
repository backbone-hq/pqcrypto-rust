//! Public ML-KEM roundtrip tests using deterministic key generation and encapsulation.

use pqcrypto_ml_kem::{mlkem1024, mlkem512, mlkem768};

#[test]
fn mlkem512_roundtrip() {
    let (pk, sk) = mlkem512::keypair_from_seed(&[0x01u8; 32]).expect("keygen");
    let enc = mlkem512::encaps_deterministic(&pk, &[0xabu8; 32]).expect("encaps");
    let dec = mlkem512::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mlkem768_roundtrip() {
    let (pk, sk) = mlkem768::keypair_from_seed(&[0x01u8; 32]).expect("keygen");
    let enc = mlkem768::encaps_deterministic(&pk, &[0xabu8; 32]).expect("encaps");
    let dec = mlkem768::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn mlkem1024_roundtrip() {
    let (pk, sk) = mlkem1024::keypair_from_seed(&[0x01u8; 32]).expect("keygen");
    let enc = mlkem1024::encaps_deterministic(&pk, &[0xabu8; 32]).expect("encaps");
    let dec = mlkem1024::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}
