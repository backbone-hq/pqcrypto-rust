//! Transcript consistency tests for ML-KEM (FIPS 203).
//!
//! Deterministic (seed, 100-iteration) transcripts over (pk, sk, ct, ss),
//! hashed and compared against committed SHA-256 goldens. The goldens match
//! the FIPS-203 shared-secret derivation (K = G(m‖H(ek))[0..32]).
//!
//! White-box: exercises the crate-internal `kem` module entry points.

use crate::kem;
use alloc::format;
use sha2::{Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

fn shake256<const OUT: usize>(input: &[u8]) -> [u8; OUT] {
    let mut shake = Shake256::default();
    Update::update(&mut shake, input);
    let mut reader = shake.finalize_xof();
    let mut out = [0u8; OUT];
    reader.read(&mut out);
    out
}

fn update_hex_line(hasher: &mut Sha256, label: &[u8], data: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    Digest::update(hasher, label);
    Digest::update(hasher, b" = ");
    for &byte in data {
        Digest::update(
            hasher,
            [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]],
        );
    }
    Digest::update(hasher, b"\n");
}

fn run_mlkem_native_transcript<const K: usize>(
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
    pk_size: usize,
    expected_sha256: &str,
    label: &str,
) {
    let seed = [
        32u8, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
        54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
        77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
    ];
    let mut coins = shake256::<96>(&seed);
    let mut transcript = Sha256::new();

    for i in 0..100 {
        coins = shake256::<96>(&coins);
        let d: [u8; 32] = coins[..32].try_into().expect("d slice length");
        let z: [u8; 32] = coins[32..64].try_into().expect("z slice length");
        let msg: [u8; 32] = coins[64..].try_into().expect("msg slice length");

        let (pk, sk) = kem::keygen_internal::<K>(eta1, eta2, &d, &z);
        let enc = kem::encaps_internal::<K>(&pk, &msg, eta1, eta2, du, dv)
            .expect("encapsulation should succeed with valid inputs");
        let dec_ss = kem::decaps_internal::<K>(&sk, &enc.ciphertext, eta1, eta2, du, dv, pk_size)
            .unwrap_or_else(|err| panic!("{label} entry {i}: decaps failed: {err:?}"));
        assert_eq!(
            dec_ss.as_slice(),
            enc.shared_secret.as_slice(),
            "{label} entry {i}: decaps shared secret mismatch"
        );

        update_hex_line(&mut transcript, b"pk", &pk);
        update_hex_line(&mut transcript, b"sk", &sk);
        update_hex_line(&mut transcript, b"ct", &enc.ciphertext);
        update_hex_line(&mut transcript, b"ss", &enc.shared_secret);
    }

    let got = transcript.finalize();
    assert_eq!(
        format!("{got:x}"),
        expected_sha256,
        "{label}: mlkem-native transcript hash mismatch"
    );
}

#[test]
fn mlkem_native_transcript_512() {
    run_mlkem_native_transcript::<2>(
        3,
        2,
        10,
        4,
        800,
        "0a2d61707a68c0cac7b2a5005def19994e4e2a25cf8dc512b1254cbaa25473c0",
        "ML-KEM-512",
    );
}

#[test]
fn mlkem_native_transcript_768() {
    run_mlkem_native_transcript::<3>(
        2,
        2,
        10,
        4,
        1184,
        "8cff42556667edbd0fec7d0b2666d7710d80db71b684f8b4852a37ece2a4c844",
        "ML-KEM-768",
    );
}

#[test]
fn mlkem_native_transcript_1024() {
    run_mlkem_native_transcript::<4>(
        2,
        2,
        11,
        5,
        1568,
        "f9c6e424f4593cca818493cfe2424178ed0caa2a3945dc1a57cbb5d99e18ad2d",
        "ML-KEM-1024",
    );
}
