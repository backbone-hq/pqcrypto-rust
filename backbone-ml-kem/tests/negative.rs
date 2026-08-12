//! ML-KEM (FIPS 203) negative tests.

use backbone_ml_kem::error::Error;
use backbone_ml_kem::mlkem512;
use backbone_pqcrypto_internals::kat::FixedRng;
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

#[test]
fn mlkem512_encapsulation_fips_203_shared_secret() {
    // FIPS 203 Algorithm 14: the shared secret IS K = G(m‖H(ek))[0..32].
    let (pk, _sk) = mlkem512::keygen_with_rng(&mut FixedRng::new(vec![0x01u8; 64])).unwrap();
    let msg = [0xabu8; 32];
    let enc = mlkem512::encaps_with_rng(&pk, &mut FixedRng::new(msg.to_vec())).unwrap();

    let h_pk = sha3_256_32(&pk.pk);
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&msg);
    g_input[32..].copy_from_slice(&h_pk);
    let g_out = sha3_512_64(&g_input);
    let k_inner = &g_out[..32];

    assert_eq!(enc.shared_secret.as_slice(), k_inner);
}

#[test]
fn mlkem512_rejects_invalid_public_key_modulus() {
    let (mut pk, _sk) = mlkem512::keygen_with_rng(&mut FixedRng::new(vec![0x01u8; 64])).unwrap();

    pk.pk[0] = 0xff;
    pk.pk[1] |= 0x0f;

    let err = mlkem512::encaps_with_rng(&pk, &mut FixedRng::new(vec![0xabu8; 32])).unwrap_err();
    assert_eq!(err, Error::InvalidPublicKey);
}

#[test]
fn mlkem512_rejects_corrupted_stored_public_key_hash() {
    let (pk, sk) = mlkem512::keygen_with_rng(&mut FixedRng::new(vec![0x01u8; 64])).unwrap();
    let enc = mlkem512::encaps_with_rng(&pk, &mut FixedRng::new(vec![0xabu8; 32])).unwrap();

    const SK_PK_OFFSET: usize = 2 * 384;
    const PK_BYTES: usize = 800;
    let mut corrupted = sk.as_ref().to_vec();
    corrupted[SK_PK_OFFSET + PK_BYTES] ^= 0x01;
    let corrupted_sk = mlkem512::SecretKey::from_bytes(&corrupted).unwrap();

    let err = mlkem512::decaps(&corrupted_sk, &enc.ciphertext).unwrap_err();
    assert_eq!(err, Error::InvalidSecretKey);
}

#[test]
fn mlkem512_rejects_oversized_secret_key() {
    let (pk, sk) = mlkem512::keygen_with_rng(&mut FixedRng::new(vec![0x01u8; 64])).unwrap();
    let enc = mlkem512::encaps_with_rng(&pk, &mut FixedRng::new(vec![0xabu8; 32])).unwrap();

    assert!(mlkem512::SecretKey::from_bytes(&sk.as_ref()[..sk.as_ref().len() / 2]).is_err());
    assert!(mlkem512::SecretKey::from_bytes(&vec![0u8; sk.as_ref().len() + 1]).is_err());
    assert!(mlkem512::SecretKey::from_bytes(&[]).is_err());

    mlkem512::decaps(&sk, &enc.ciphertext).expect("valid decaps should succeed");
}

#[test]
fn mlkem512_seed_lengths_are_fixed_by_type() {
    // Keygen randomness `(d, z)` is 64 bytes and encaps message `m` is 32
    // bytes — both fixed by the API type, so wrong-length inputs are
    // unrepresentable.
    let (pk, _sk) = mlkem512::keygen_with_rng(&mut FixedRng::new(vec![0u8; 64])).unwrap();
    let enc = mlkem512::encaps_with_rng(&pk, &mut FixedRng::new(vec![0u8; 32])).unwrap();
    assert_eq!(enc.shared_secret.len(), 32);
}

#[test]
fn mlkem512_corrupted_ciphertext_uses_j_rejection_key() {
    let (pk, sk) = mlkem512::keygen_with_rng(&mut FixedRng::new(vec![0x01u8; 64])).unwrap();
    let enc = mlkem512::encaps_with_rng(&pk, &mut FixedRng::new(vec![0xabu8; 32])).unwrap();
    let mut ct = enc.ciphertext.clone();
    ct[0] ^= 0x01;

    const SK_PK_OFFSET: usize = 2 * 384;
    const PK_BYTES: usize = 800;
    const Z_OFFSET: usize = SK_PK_OFFSET + PK_BYTES + 32;
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
    assert!(kem_source.contains("u8::conditional_select(&k_prime[i], &rejection_key[i], fail)"));
    assert!(!kem_source.contains("ct == ct_prime"));
    assert!(!kem_source.contains("ct_prime.as_slice()"));
}
