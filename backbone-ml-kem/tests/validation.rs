//! Higher-confidence validation on the ML-KEM public API.
//!
//! 1. `Encapsulation`'s `Debug` redacts the shared secret;
//!    this test guards against regression.
//! 2. Robustness: decaps/encaps must never panic on malformed inputs —
//!    a panic on attacker-influenced data would be a timing oracle.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::unwrap_used
)]

use backbone_ml_kem::mlkem768;
use backbone_pqcrypto_internals::kat::FixedRng;
use backbone_pqcrypto_internals::testutil::XorShift;

/// Regression proof: the public `Encapsulation` Debug impl redacts the
/// shared secret. Marker bytes are planted in the secret; if Debug ever
/// regresses to a derived impl, the exact decimal rendering of the secret
/// appears in the output and this test fails.
#[test]
fn encapsulation_debug_redacts_shared_secret() {
    let (pk, _sk) = mlkem768::keygen_with_rng(&mut FixedRng::new(vec![7u8; 64])).expect("keygen");
    let mut enc =
        mlkem768::encaps_with_rng(&pk, &mut FixedRng::new(vec![9u8; 32])).expect("encaps");
    enc.shared_secret[0] = 200; // identifiable marker byte
    enc.shared_secret[31] = 201;
    let dbg = format!("{enc:?}");

    let ss_decimal = enc
        .shared_secret
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    assert!(
        !dbg.contains(&ss_decimal),
        "regression: Debug exposes the shared secret. got: {dbg}"
    );
    assert!(
        dbg.contains("REDACTED"),
        "Debug should mark the shared secret as redacted. got: {dbg}"
    );
}

/// decaps must never panic: correct-length random ciphertexts exercise the
/// full decrypt + FO re-encryption path; wrong lengths hit the public length
/// check. All outcomes (Ok/Err) are acceptable; a panic is a failure.
#[test]
fn decaps_never_panics_on_random_ciphertexts() {
    let (pk, sk) = mlkem768::keygen_with_rng(&mut FixedRng::new(vec![3u8; 64])).expect("keygen");
    let mut rng = XorShift::new();
    for _ in 0..2000 {
        let mut ct = vec![0u8; 1088]; // CT_BYTES for ML-KEM-768
        rng.fill(&mut ct);
        let _ = mlkem768::decaps(&sk, &ct);
    }
    for _ in 0..500 {
        let len = (rng.next_u64() % 1600) as usize;
        let ct = vec![0u8; len];
        let _ = mlkem768::decaps(&sk, &ct);
    }
    let _ = pk;
}

/// encaps must never panic on garbage public keys.
#[test]
fn encaps_never_panics_on_garbage_public_keys() {
    let mut rng = XorShift::new();
    for _ in 0..500 {
        let mut pk_bytes = vec![0u8; 1184]; // PK_BYTES for ML-KEM-768
        rng.fill(&mut pk_bytes);
        if let Ok(garbage) = mlkem768::PublicKey::from_bytes(&pk_bytes) {
            let _ = mlkem768::encaps(&garbage);
        }
    }
}
