//! Negative tests for NTRU LPRime.

use pqcrypto_ntruplr::error::Error;
use pqcrypto_ntruplr::{ntruplr653, ntruplr761};

#[test]
fn ntruplr653_wrong_key_and_tampering_use_fallback_secret() {
    let (pk_a, _sk_a) = ntruplr653::keypair_from_seed(&[0x42u8; 48]).expect("keygen A");
    let (_pk_b, sk_b) = ntruplr653::keypair_from_seed(&[0x99u8; 48]).expect("keygen B");
    let enc =
        ntruplr653::encaps_deterministic(&pk_a, &[0x13u8; 32]).expect("encaps should succeed");

    let wrong_key_ss = ntruplr653::decaps(&sk_b, &enc.ciphertext).expect("decaps should succeed");
    assert_ne!(wrong_key_ss, enc.shared_secret);

    for pos in [
        0usize,
        1,
        enc.ciphertext.len() / 3,
        enc.ciphertext.len() / 2,
        enc.ciphertext.len() - 1,
    ] {
        let mut ct = enc.ciphertext.clone();
        ct[pos] ^= 0xff;
        let tampered_ss = ntruplr653::decaps(
            &ntruplr653::SecretKey::from_bytes(_sk_a.as_ref()).unwrap(),
            &ct,
        )
        .expect("same-length tampered ciphertext uses fallback");
        assert_ne!(tampered_ss, enc.shared_secret, "tampered byte {pos}");
    }
}

#[test]
fn ntruplr761_wrong_key_and_tampering_use_fallback_secret() {
    let (pk_a, _sk_a) = ntruplr761::keypair_from_seed(&[0x42u8; 48]).expect("keygen A");
    let (_pk_b, sk_b) = ntruplr761::keypair_from_seed(&[0x99u8; 48]).expect("keygen B");
    let enc =
        ntruplr761::encaps_deterministic(&pk_a, &[0x13u8; 32]).expect("encaps should succeed");

    let wrong_key_ss = ntruplr761::decaps(&sk_b, &enc.ciphertext).expect("decaps should succeed");
    assert_ne!(wrong_key_ss, enc.shared_secret);

    for pos in [
        0usize,
        1,
        enc.ciphertext.len() / 3,
        enc.ciphertext.len() / 2,
        enc.ciphertext.len() - 1,
    ] {
        let mut ct = enc.ciphertext.clone();
        ct[pos] ^= 0xff;
        let tampered_ss = ntruplr761::decaps(
            &ntruplr761::SecretKey::from_bytes(_sk_a.as_ref()).unwrap(),
            &ct,
        )
        .expect("same-length tampered ciphertext uses fallback");
        assert_ne!(tampered_ss, enc.shared_secret, "tampered byte {pos}");
    }
}

#[test]
fn ntruplr653_rejects_invalid_lengths() {
    let (pk, sk) = ntruplr653::keypair_from_seed(&[0x42u8; 48]).expect("keygen");
    let enc = ntruplr653::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps should succeed");

    assert_eq!(
        ntruplr653::decaps(&sk, &[]).expect_err("empty ct"),
        Error::InvalidCiphertextLength
    );
    assert_eq!(
        ntruplr653::decaps(&sk, &enc.ciphertext[..enc.ciphertext.len() - 1])
            .expect_err("truncated ct"),
        Error::InvalidCiphertextLength
    );
    assert_eq!(
        ntruplr653::decaps(&sk, &[enc.ciphertext.as_slice(), &[0u8]].concat(),)
            .expect_err("oversized ct"),
        Error::InvalidCiphertextLength
    );

    // SecretKey::from_bytes rejects wrong-length inputs
    assert!(ntruplr653::SecretKey::from_bytes(&[0u8; 1]).is_err());
    assert!(ntruplr653::SecretKey::from_bytes(&vec![0u8; 1124]).is_err());
    assert!(ntruplr653::SecretKey::from_bytes(&vec![0u8; 1126]).is_err());

    let short_pk = ntruplr653::PublicKey {
        pk: pk.pk[..pk.pk.len() - 1].to_vec(),
    };
    assert_eq!(
        ntruplr653::encaps_deterministic(&short_pk, &[0x13u8; 32]).expect_err("short pk"),
        Error::InvalidKeyLength
    );
    assert_eq!(
        ntruplr653::encaps_deterministic(&pk, &[0x13u8; 31]).expect_err("short seed"),
        Error::InvalidKeyLength
    );
}

#[test]
fn ntruplr761_rejects_invalid_lengths() {
    let (pk, sk) = ntruplr761::keypair_from_seed(&[0x42u8; 48]).expect("keygen");
    let enc = ntruplr761::encaps_deterministic(&pk, &[0x13u8; 32]).expect("encaps should succeed");

    assert_eq!(
        ntruplr761::decaps(&sk, &[]).expect_err("empty ct"),
        Error::InvalidCiphertextLength
    );
    assert_eq!(
        ntruplr761::decaps(&sk, &enc.ciphertext[..enc.ciphertext.len() - 1])
            .expect_err("truncated ct"),
        Error::InvalidCiphertextLength
    );
    assert_eq!(
        ntruplr761::decaps(&sk, &[enc.ciphertext.as_slice(), &[0u8]].concat(),)
            .expect_err("oversized ct"),
        Error::InvalidCiphertextLength
    );

    // SecretKey::from_bytes rejects wrong-length inputs
    assert!(ntruplr761::SecretKey::from_bytes(&[0u8; 1]).is_err());
    assert!(ntruplr761::SecretKey::from_bytes(&vec![0u8; 1293]).is_err());
    assert!(ntruplr761::SecretKey::from_bytes(&vec![0u8; 1295]).is_err());

    let short_pk = ntruplr761::PublicKey {
        pk: pk.pk[..pk.pk.len() - 1].to_vec(),
    };
    assert_eq!(
        ntruplr761::encaps_deterministic(&short_pk, &[0x13u8; 32]).expect_err("short pk"),
        Error::InvalidKeyLength
    );
    assert_eq!(
        ntruplr761::encaps_deterministic(&pk, &[0x13u8; 31]).expect_err("short seed"),
        Error::InvalidKeyLength
    );
}
