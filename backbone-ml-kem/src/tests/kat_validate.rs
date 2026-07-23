//! ML-KEM (FIPS 203) KAT validation against NIST ACVP keygen vectors.

use std::{format, path::PathBuf};

use crate::kem;
use backbone_pqcrypto_internals::kat::parse_kat_file;
use sha2::{Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Run KAT validation for a given ML-KEM variant.
///
/// # Panics
/// Panics on the first KAT mismatch with a descriptive message.
fn run_mlkem_kat<const K: usize>(
    kat_file: &str,
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
    pk_size: usize,
    label: &str,
) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push(kat_file);

    let entries = parse_kat_file(path.to_str().expect("KAT path is valid UTF-8"));
    assert!(!entries.is_empty(), "No KAT entries found in {kat_file}");

    for (i, entry) in entries.iter().enumerate() {
        let d: &[u8] = entry
            .get("d")
            .unwrap_or_else(|| panic!("entry {i}: missing 'd'"));
        let z: &[u8] = entry
            .get("z")
            .unwrap_or_else(|| panic!("entry {i}: missing 'z'"));
        let expected_pk = entry
            .get("pk")
            .unwrap_or_else(|| panic!("entry {i}: missing 'pk'"));
        let expected_sk = entry
            .get("sk")
            .unwrap_or_else(|| panic!("entry {i}: missing 'sk'"));
        let msg: &[u8] = entry
            .get("msg")
            .unwrap_or_else(|| panic!("entry {i}: missing 'msg'"));

        let d_arr: [u8; 32] = d.try_into().expect("d must be 32 bytes");
        let z_arr: [u8; 32] = z.try_into().expect("z must be 32 bytes");
        let msg_arr: [u8; 32] = msg.try_into().expect("msg must be 32 bytes");

        let (pk, sk) = kem::keygen_internal::<K>(eta1, eta2, &d_arr, &z_arr);

        assert_eq!(pk, expected_pk.as_slice(), "{label} entry {i}: PK mismatch");
        assert_eq!(sk, expected_sk.as_slice(), "{label} entry {i}: SK mismatch");

        let enc = kem::encaps_internal::<K>(&pk, &msg_arr, eta1, eta2, du, dv)
            .expect("encapsulation should succeed with valid inputs");

        let dec_ss = kem::decaps_internal::<K>(&sk, &enc.ciphertext, eta1, eta2, du, dv, pk_size)
            .expect("decapsulation should pass hash check");

        assert_eq!(
            dec_ss.as_slice(),
            enc.shared_secret.as_slice(),
            "{label} entry {i}: decaps shared secret mismatch"
        );
    }
}

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

/// Regenerate the official mlkem-native KAT transcript and compare it to the
/// upstream hash in `/tmp/backbone_refs/mlkem-native/META.yml`.
fn run_mlkem_native_transcript_kat<const K: usize>(
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
fn kat_mlkem512() {
    run_mlkem_kat::<2>("mlkem512.rsp", 3, 2, 10, 4, 800, "ML-KEM-512");
}

#[test]
fn mlkem_native_transcript_512() {
    run_mlkem_native_transcript_kat::<2>(
        3,
        2,
        10,
        4,
        800,
        "a5e1e14fec3f1dd2d58c35c92992e5bb4c5e9cc2d4101a619c3df494b1036eb5",
        "ML-KEM-512",
    );
}

#[test]
fn kat_mlkem768() {
    run_mlkem_kat::<3>("mlkem768.rsp", 2, 2, 10, 4, 1184, "ML-KEM-768");
}

#[test]
fn mlkem_native_transcript_768() {
    run_mlkem_native_transcript_kat::<3>(
        2,
        2,
        10,
        4,
        1184,
        "1235c2eba5bc17ccacc2c1e217d35068fc17fff81b94fd0d55b031c8d45e953c",
        "ML-KEM-768",
    );
}

#[test]
fn kat_mlkem1024() {
    run_mlkem_kat::<4>("mlkem1024.rsp", 2, 2, 11, 5, 1568, "ML-KEM-1024");
}

#[test]
fn mlkem_native_transcript_1024() {
    run_mlkem_native_transcript_kat::<4>(
        2,
        2,
        11,
        5,
        1568,
        "772d9e86f0b2746cf08f3732a5c117a898208d1d5e2809669ea67bbe3a6b4c87",
        "ML-KEM-1024",
    );
}
