//! Public NTRUPLR roundtrip tests using deterministic key generation and encapsulation.

use backbone_ntruplr::{ntruplr653, ntruplr761};

#[test]
fn ntruplr653_roundtrip() {
    let (pk, sk) = ntruplr653::keypair_from_seed(&[0x42u8; 48]).expect("keygen");
    let enc = ntruplr653::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = ntruplr653::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}

#[test]
fn ntruplr761_roundtrip() {
    let (pk, sk) = ntruplr761::keypair_from_seed(&[0x42u8; 48]).expect("keygen");
    let enc = ntruplr761::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps");
    let dec = ntruplr761::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(enc.shared_secret, dec);
}
