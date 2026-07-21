//! Public Streamlined NTRU Prime roundtrip tests using deterministic key generation and encapsulation.

use backbone_sntrup::{sntrup653, sntrup761, sntrup857};

#[test]
fn sntrup653_roundtrip() {
    let (pk, sk) = sntrup653::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = sntrup653::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = sntrup653::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn sntrup761_roundtrip() {
    let (pk, sk) = sntrup761::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = sntrup761::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = sntrup761::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn sntrup857_roundtrip() {
    let (pk, sk) = sntrup857::keypair_from_seed(&[0x42u8; 32]).expect("keygen");
    let enc = sntrup857::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = sntrup857::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}
