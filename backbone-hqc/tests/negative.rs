//! HQC (FIPS 207) negative tests.
//!
//! Per-variant negative coverage (wrong-key fallback, corrupted ciphertext,
//! invalid ct/sk lengths) is emitted inline by the `define_variant!` macro
//! in `src/macros.rs` (tests run in every variant module automatically).
//! This file keeps only the tests that are not per-variant.

use backbone_hqc::hqc128;
use backbone_pqcrypto_internals::kat::FixedRng;

#[test]
fn hqc128_seed_length_is_fixed_by_type() {
    // Seed lengths are fixed by the API type now; nothing to reject.
    let (pk, _sk) = hqc128::keygen_with_rng(&mut FixedRng::new(vec![0x42u8; 48])).expect("keygen");
    let enc = hqc128::encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48])).expect("encaps");
    assert_eq!(enc.shared_secret.len(), 32);
}
