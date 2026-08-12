//! Higher-confidence validation on the ML-DSA public API.
//!
//! Robustness: verify/sign must never panic on malformed inputs — a panic on
//! attacker-influenced data would be a timing oracle. Correct-length
//! garbage signatures and public keys exercise the full verify path.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::unwrap_used
)]

use backbone_ml_dsa::mldsa65;
use backbone_pqcrypto_internals::kat::FixedRng;
use backbone_pqcrypto_internals::testutil::XorShift;

/// verify must never panic on correct-length garbage signatures.
#[test]
fn verify_never_panics_on_garbage_signatures() {
    let (pk, _sk) = mldsa65::keygen_with_rng(&mut FixedRng::new(vec![5u8; 32])).expect("keygen");
    let mut rng = XorShift::new();
    for _ in 0..500 {
        let mut sig = vec![0u8; 3309]; // SIG_BYTES for ML-DSA-65
        rng.fill(&mut sig);
        let sig = mldsa65::Signature::from_bytes(&sig).expect("sig len");
        let _ = mldsa65::verify(&pk, b"msg", &sig, None, None);
    }
}

/// verify must never panic on garbage public keys.
#[test]
fn verify_never_panics_on_garbage_public_keys() {
    let (_pk, sk) = mldsa65::keygen_with_rng(&mut FixedRng::new(vec![6u8; 32])).expect("keygen");
    let sig = mldsa65::sign(&sk, b"msg", None, None).expect("sign");
    let mut rng = XorShift::new();
    for _ in 0..500 {
        let mut pk_bytes = vec![0u8; 1952]; // PK_BYTES for ML-DSA-65
        rng.fill(&mut pk_bytes);
        if let Ok(garbage_pk) = mldsa65::PublicKey::from_bytes(&pk_bytes) {
            let _ = mldsa65::verify(&garbage_pk, b"msg", &sig, None, None);
        }
    }
}

/// sign must not panic on attacker-chosen messages / randomness.
#[test]
fn sign_never_panics_on_arbitrary_messages() {
    let (_pk, sk) = mldsa65::keygen_with_rng(&mut FixedRng::new(vec![8u8; 32])).expect("keygen");
    let mut rng = XorShift::new();
    for len in [0usize, 1, 16, 255, 1024] {
        let mut msg = vec![0u8; len];
        rng.fill(&mut msg);
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let _ = mldsa65::sign_with_rng(&sk, &msg, &mut FixedRng::new(seed.to_vec()), None, None);
    }
}
