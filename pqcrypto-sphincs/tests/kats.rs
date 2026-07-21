//! Known Answer Test validation for SPHINCS+.
//! Verifies both signature verification and key generation against NIST .rsp vectors.
use std::fs;
use std::path::PathBuf;

use pqcrypto_sphincs::params::Params;
use pqcrypto_sphincs::params::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s,
};
use pqcrypto_sphincs::sha2_128f;
use pqcrypto_sphincs::sha2_128s;
use pqcrypto_sphincs::sha2_192f;
use pqcrypto_sphincs::sha2_192s;
use pqcrypto_sphincs::sha2_256f;
use pqcrypto_sphincs::sha2_256s;
use pqcrypto_sphincs::shake128f;
use pqcrypto_sphincs::shake128s;
use pqcrypto_sphincs::shake192f;
use pqcrypto_sphincs::shake192s;
use pqcrypto_sphincs::shake256f;
use pqcrypto_sphincs::shake256s;

fn kat_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("kats")
}

fn parse_hex_line(line: &str) -> Vec<u8> {
    let hex = line.split(" = ").nth(1).expect("missing = in line");
    hex::decode(hex.trim()).expect("hex decode failed")
}

// ── Signature verification KATs ──

macro_rules! kat_verify_test {
    ($name:ident, $module:ident, $variant:ty, $variant_name:literal) => {
        #[test]
        fn $name() {
            let path = kat_dir().join(format!("sphincs-{}-simple.rsp", $variant_name));
            let contents = fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!("Failed to read KAT file {:?}: {}", path, e);
            });

            let mut pk_raw = Vec::new();
            let mut msg_raw = Vec::new();
            let mut sm_raw = Vec::new();

            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if line.starts_with("pk =") {
                    pk_raw = parse_hex_line(line);
                } else if line.starts_with("msg =") {
                    msg_raw = parse_hex_line(line);
                } else if line.starts_with("sm =") {
                    sm_raw = parse_hex_line(line);
                }
            }

            assert_eq!(
                pk_raw.len(),
                <$variant>::PK_BYTES,
                "PK size mismatch for {}",
                $variant_name
            );
            assert_eq!(
                sm_raw.len(),
                <$variant>::SIG_BYTES + msg_raw.len(),
                "sm length mismatch for {}",
                $variant_name
            );

            let sig_bytes = &sm_raw[..<$variant>::SIG_BYTES];
            let msg_from_sm = &sm_raw[<$variant>::SIG_BYTES..];
            assert_eq!(
                msg_from_sm,
                &msg_raw[..],
                "msg portion of sm doesn't match msg field"
            );

            let pk = $module::PublicKey { pk: pk_raw.clone() };
            let sig = $module::Signature {
                sig: sig_bytes.to_vec(),
            };

            assert!(
                $module::verify_submission(&pk, &msg_raw, &sig),
                "Verification failed for {}",
                $variant_name
            );
        }
    };
}

kat_verify_test!(kat_shake_128s, shake128s, Shake128s, "shake-128s");
kat_verify_test!(kat_shake_128f, shake128f, Shake128f, "shake-128f");
kat_verify_test!(kat_shake_192s, shake192s, Shake192s, "shake-192s");
kat_verify_test!(kat_shake_192f, shake192f, Shake192f, "shake-192f");
kat_verify_test!(kat_shake_256s, shake256s, Shake256s, "shake-256s");
kat_verify_test!(kat_shake_256f, shake256f, Shake256f, "shake-256f");
kat_verify_test!(kat_sha2_128s, sha2_128s, Sha2_128s, "sha2-128s");
kat_verify_test!(kat_sha2_128f, sha2_128f, Sha2_128f, "sha2-128f");
kat_verify_test!(kat_sha2_192s, sha2_192s, Sha2_192s, "sha2-192s");
kat_verify_test!(kat_sha2_192f, sha2_192f, Sha2_192f, "sha2-192f");
kat_verify_test!(kat_sha2_256s, sha2_256s, Sha2_256s, "sha2-256s");
kat_verify_test!(kat_sha2_256f, sha2_256f, Sha2_256f, "sha2-256f");

// ── Sign-output byte-for-byte KATs ──

macro_rules! kat_sign_test {
    ($name:ident, $module:ident, $variant:ty, $variant_name:literal) => {
        #[test]
        fn $name() {
            let path = kat_dir().join(format!("sphincs-{}-simple.rsp", $variant_name));
            let contents = fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!("Failed to read KAT file {:?}: {}", path, e);
            });

            let mut _pk_raw = Vec::new();
            let mut msg_raw = Vec::new();
            let mut sk_raw = Vec::new();
            let mut sm_raw = Vec::new();

            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if line.starts_with("pk =") {
                    _pk_raw = parse_hex_line(line);
                } else if line.starts_with("msg =") {
                    msg_raw = parse_hex_line(line);
                } else if line.starts_with("sk =") {
                    sk_raw = parse_hex_line(line);
                } else if line.starts_with("sm =") {
                    sm_raw = parse_hex_line(line);
                }
            }

            let sig_expected = &sm_raw[..<$variant>::SIG_BYTES];
            let keygen_seed = &sk_raw[..<$variant>::SEED_BYTES];
            let optrand = vec![0u8; <$variant>::N];

            let (_pk, sk) = $module::keygen(keygen_seed).unwrap();
            let sig = $module::sign_deterministic_submission(&sk, &msg_raw, &optrand).unwrap();

            assert_eq!(
                sig.sig.len(),
                sig_expected.len(),
                "signature length mismatch for {}",
                $variant_name
            );
            assert_eq!(
                sig.sig, sig_expected,
                "signature mismatch for {}!",
                $variant_name
            );
        }
    };
}

kat_sign_test!(kat_sign_shake_128s, shake128s, Shake128s, "shake-128s");
kat_sign_test!(kat_sign_shake_128f, shake128f, Shake128f, "shake-128f");
kat_sign_test!(kat_sign_shake_192s, shake192s, Shake192s, "shake-192s");
kat_sign_test!(kat_sign_shake_192f, shake192f, Shake192f, "shake-192f");
kat_sign_test!(kat_sign_shake_256s, shake256s, Shake256s, "shake-256s");
kat_sign_test!(kat_sign_shake_256f, shake256f, Shake256f, "shake-256f");
kat_sign_test!(kat_sign_sha2_128s, sha2_128s, Sha2_128s, "sha2-128s");
kat_sign_test!(kat_sign_sha2_128f, sha2_128f, Sha2_128f, "sha2-128f");
kat_sign_test!(kat_sign_sha2_192s, sha2_192s, Sha2_192s, "sha2-192s");
kat_sign_test!(kat_sign_sha2_192f, sha2_192f, Sha2_192f, "sha2-192f");
kat_sign_test!(kat_sign_sha2_256s, sha2_256s, Sha2_256s, "sha2-256s");
kat_sign_test!(kat_sign_sha2_256f, sha2_256f, Sha2_256f, "sha2-256f");

// ── Key generation KATs ──

macro_rules! kat_keygen_test {
    ($name:ident, $module:ident, $variant:ty, $variant_name:literal) => {
        #[test]
        fn $name() {
            let path = kat_dir().join(format!("sphincs-{}-simple.rsp", $variant_name));
            let contents = fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!("Failed to read KAT file {:?}: {}", path, e);
            });

            let mut pk_expected = Vec::new();
            let mut sk_raw = Vec::new();

            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if line.starts_with("pk") {
                    pk_expected = parse_hex_line(line);
                } else if line.starts_with("sk") {
                    sk_raw = parse_hex_line(line);
                }
            }

            assert!(!sk_raw.is_empty(), "no sk found for {}", $variant_name);
            assert_eq!(
                sk_raw.len(),
                <$variant>::SK_BYTES,
                "SK size mismatch for {}",
                $variant_name
            );
            assert_eq!(
                pk_expected.len(),
                <$variant>::PK_BYTES,
                "PK size mismatch for {}",
                $variant_name
            );

            let keygen_seed = &sk_raw[..<$variant>::SEED_BYTES];
            assert_eq!(keygen_seed.len(), <$variant>::SEED_BYTES);

            let (pk, _sk_out) = $module::keygen(keygen_seed).unwrap();
            assert_eq!(
                pk.pk.len(),
                <$variant>::PK_BYTES,
                "Rust PK size mismatch for {}",
                $variant_name
            );
            assert_eq!(pk.pk, pk_expected, "PK mismatch for {}!", $variant_name);
        }
    };
}

kat_keygen_test!(kat_keygen_shake_128s, shake128s, Shake128s, "shake-128s");
kat_keygen_test!(kat_keygen_shake_128f, shake128f, Shake128f, "shake-128f");
kat_keygen_test!(kat_keygen_shake_192s, shake192s, Shake192s, "shake-192s");
kat_keygen_test!(kat_keygen_shake_192f, shake192f, Shake192f, "shake-192f");
kat_keygen_test!(kat_keygen_shake_256s, shake256s, Shake256s, "shake-256s");
kat_keygen_test!(kat_keygen_shake_256f, shake256f, Shake256f, "shake-256f");
kat_keygen_test!(kat_keygen_sha2_128s, sha2_128s, Sha2_128s, "sha2-128s");
kat_keygen_test!(kat_keygen_sha2_128f, sha2_128f, Sha2_128f, "sha2-128f");
kat_keygen_test!(kat_keygen_sha2_192s, sha2_192s, Sha2_192s, "sha2-192s");
kat_keygen_test!(kat_keygen_sha2_192f, sha2_192f, Sha2_192f, "sha2-192f");
kat_keygen_test!(kat_keygen_sha2_256s, sha2_256s, Sha2_256s, "sha2-256s");
kat_keygen_test!(kat_keygen_sha2_256f, sha2_256f, Sha2_256f, "sha2-256f");
