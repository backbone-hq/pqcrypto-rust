//! Higher-confidence validation on the Streamlined NTRU Prime public API.
//!
//! Robustness: decaps/encaps must never panic on malformed inputs — a panic
//! on attacker-influenced data would be a timing oracle. All outcomes
//! (Ok/Err) are acceptable; a panic is a failure.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::unwrap_used
)]

use backbone_pqcrypto_internals::kat::FixedRng;
use backbone_pqcrypto_internals::testutil::XorShift;
use backbone_sntrup::sntrup761;

/// decaps must never panic: correct-length random ciphertexts exercise the
/// full decrypt + fallback path; wrong lengths hit the public length check.
#[test]
fn decaps_never_panics_on_random_ciphertexts() {
    let (pk, sk) = sntrup761::keygen_with_rng(&mut FixedRng::new(vec![3u8; 48])).expect("keygen");
    let enc = sntrup761::encaps_with_rng(&pk, &mut FixedRng::new(vec![7u8; 48])).expect("encaps");
    let ct_len = enc.ciphertext.len();
    let mut rng = XorShift::new();
    for _ in 0..1000 {
        let mut ct = vec![0u8; ct_len];
        rng.fill(&mut ct);
        let _ = sntrup761::decaps(&sk, &ct);
    }
    for _ in 0..300 {
        let len = (rng.next_u64() % (ct_len as u64 * 2 + 1)) as usize;
        let ct = vec![0u8; len];
        let _ = sntrup761::decaps(&sk, &ct);
    }
}

/// encaps must never panic on garbage public keys.
#[test]
fn encaps_never_panics_on_garbage_public_keys() {
    let (pk, _sk) = sntrup761::keygen_with_rng(&mut FixedRng::new(vec![3u8; 48])).expect("keygen");
    let pk_len = pk.pk.len();
    let mut rng = XorShift::new();
    for _ in 0..300 {
        let mut pk_bytes = vec![0u8; pk_len];
        rng.fill(&mut pk_bytes);
        if let Ok(garbage) = sntrup761::PublicKey::from_bytes(&pk_bytes) {
            let _ = sntrup761::encaps(&garbage);
        }
    }
}
