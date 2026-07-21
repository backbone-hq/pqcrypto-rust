//! KAT validation tests for ML-DSA variants.
#![allow(clippy::std_instead_of_alloc)]

use pqcrypto_ml_dsa::mldsa44;
use pqcrypto_ml_dsa::mldsa65;
use pqcrypto_ml_dsa::mldsa87;
use pqcrypto_ml_dsa::params::{Mldsa44, Mldsa65, Mldsa87, Params};
use std::collections::HashMap;

struct KatEntry {
    seed: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    msg: Vec<u8>,
    sm: Vec<u8>,
}

fn map_to_entry(map: HashMap<String, Vec<u8>>) -> KatEntry {
    KatEntry {
        seed: map.get("xi").expect("Missing xi").clone(),
        pk: map.get("pk").expect("Missing pk").clone(),
        sk: map.get("sk").expect("Missing sk").clone(),
        msg: map.get("msg").expect("Missing msg").clone(),
        sm: map.get("sm").expect("Missing sm").clone(),
    }
}

fn get_kat_entries(path: &str) -> Vec<KatEntry> {
    pqcrypto_utils::kat::parse_kat_file(path)
        .into_iter()
        .map(map_to_entry)
        .collect()
}

const KAT_DIR: &str = "tests";

fn kat_path(name: &str) -> String {
    format!("{}/{}.rsp", KAT_DIR, name)
}

#[test]
fn test_ml_dsa_44_roundtrip_basic() {
    let seed =
        hex::decode("f696484048ec21f96cf50a56d0759c448f3779752f0383d37449690694cf7a68").unwrap();
    let msg = b"test message 1234567890123456";
    let (pk, sk) = mldsa44::keygen(&seed).unwrap();
    let sig = mldsa44::sign(&sk, msg).unwrap();
    let valid = mldsa44::verify(&pk, msg, &sig);
    assert!(valid, "Basic roundtrip should pass");
}

// ─── Keygen KATs ───────────────────────────────────────────────────────────

#[test]
fn test_ml_dsa_44_keygen_kat() {
    let entries = get_kat_entries(&kat_path("mldsa44-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (pk, sk) = mldsa44::keygen(&entry.seed).unwrap();
        assert_eq!(pk.pk, entry.pk, "KAT entry {i}: pk mismatch");
        assert_eq!(sk.as_ref(), entry.sk, "KAT entry {i}: sk mismatch");
    }
}

#[test]
fn test_ml_dsa_65_keygen_kat() {
    let entries = get_kat_entries(&kat_path("mldsa65-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (pk, sk) = mldsa65::keygen(&entry.seed).unwrap();
        assert_eq!(pk.pk, entry.pk, "KAT entry {i}: pk mismatch");
        assert_eq!(sk.as_ref(), entry.sk, "KAT entry {i}: sk mismatch");
    }
}

#[test]
fn test_ml_dsa_87_keygen_kat() {
    let entries = get_kat_entries(&kat_path("mldsa87-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (pk, sk) = mldsa87::keygen(&entry.seed).unwrap();
        assert_eq!(pk.pk, entry.pk, "KAT entry {i}: pk mismatch");
        assert_eq!(sk.as_ref(), entry.sk, "KAT entry {i}: sk mismatch");
    }
}

// ─── Sign KATs ─────────────────────────────────────────────────────────────

#[test]
fn test_ml_dsa_44_sign_kat() {
    let entries = get_kat_entries(&kat_path("mldsa44-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (pk, sk) = mldsa44::keygen(&entry.seed).unwrap();
        let sig = mldsa44::sign(&sk, &entry.msg).unwrap();
        assert!(
            mldsa44::verify(&pk, &entry.msg, &sig),
            "KAT entry {i}: sign-produced signature fails verify"
        );
    }
}

#[test]
fn test_ml_dsa_65_sign_kat() {
    let entries = get_kat_entries(&kat_path("mldsa65-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (pk, sk) = mldsa65::keygen(&entry.seed).unwrap();
        let sig = mldsa65::sign(&sk, &entry.msg).unwrap();
        assert!(
            mldsa65::verify(&pk, &entry.msg, &sig),
            "KAT entry {i}: sign-produced signature fails verify"
        );
    }
}

#[test]
fn test_ml_dsa_87_sign_kat() {
    let entries = get_kat_entries(&kat_path("mldsa87-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (pk, sk) = mldsa87::keygen(&entry.seed).unwrap();
        let sig = mldsa87::sign(&sk, &entry.msg).unwrap();
        assert!(
            mldsa87::verify(&pk, &entry.msg, &sig),
            "KAT entry {i}: sign-produced signature fails verify"
        );
    }
}

// ─── Sign-output byte-for-byte KATs ────────────────────────────────────────

#[test]
fn test_ml_dsa_44_sign_output_kat() {
    let entries = get_kat_entries(&kat_path("mldsa44-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (_pk, sk) = mldsa44::keygen(&entry.seed).unwrap();
        let sm = &entry.sm;
        let sig_expected = &sm[..Mldsa44::SIGNATURE_BYTES];
        let sig = mldsa44::sign_deterministic(&sk, &entry.msg, &[0u8; 32]).unwrap();
        assert_eq!(sig.sig, sig_expected, "KAT entry {i}: sign output mismatch");
    }
}

#[test]
fn test_ml_dsa_65_sign_output_kat() {
    let entries = get_kat_entries(&kat_path("mldsa65-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (_pk, sk) = mldsa65::keygen(&entry.seed).unwrap();
        let sm = &entry.sm;
        let sig_expected = &sm[..Mldsa65::SIGNATURE_BYTES];
        let sig = mldsa65::sign_deterministic(&sk, &entry.msg, &[0u8; 32]).unwrap();
        assert_eq!(sig.sig, sig_expected, "KAT entry {i}: sign output mismatch");
    }
}

#[test]
fn test_ml_dsa_87_sign_output_kat() {
    let entries = get_kat_entries(&kat_path("mldsa87-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (_pk, sk) = mldsa87::keygen(&entry.seed).unwrap();
        let sm = &entry.sm;
        let sig_expected = &sm[..Mldsa87::SIGNATURE_BYTES];
        let sig = mldsa87::sign_deterministic(&sk, &entry.msg, &[0u8; 32]).unwrap();
        assert_eq!(sig.sig, sig_expected, "KAT entry {i}: sign output mismatch");
    }
}

// ─── Verify KATs ───────────────────────────────────────────────────────────

#[test]
fn test_ml_dsa_44_verify_kat() {
    let entries = get_kat_entries(&kat_path("mldsa44-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let pk = mldsa44::PublicKey {
            pk: entry.pk.clone(),
        };
        let sig = mldsa44::Signature {
            sig: entry.sm[..Mldsa44::SIGNATURE_BYTES].to_vec(),
        };
        assert!(
            mldsa44::verify(&pk, &entry.msg, &sig),
            "KAT entry {i}: KAT signature fails verify (msg_len={})",
            entry.msg.len()
        );
    }
}

#[test]
fn test_ml_dsa_65_verify_kat() {
    let entries = get_kat_entries(&kat_path("mldsa65-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let pk = mldsa65::PublicKey {
            pk: entry.pk.clone(),
        };
        let sig = mldsa65::Signature {
            sig: entry.sm[..Mldsa65::SIGNATURE_BYTES].to_vec(),
        };
        assert!(
            mldsa65::verify(&pk, &entry.msg, &sig),
            "KAT entry {i}: KAT signature fails verify (msg_len={})",
            entry.msg.len()
        );
    }
}

#[test]
fn test_ml_dsa_87_verify_kat() {
    let entries = get_kat_entries(&kat_path("mldsa87-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let pk = mldsa87::PublicKey {
            pk: entry.pk.clone(),
        };
        let sig = mldsa87::Signature {
            sig: entry.sm[..Mldsa87::SIGNATURE_BYTES].to_vec(),
        };
        assert!(
            mldsa87::verify(&pk, &entry.msg, &sig),
            "KAT entry {i}: KAT signature fails verify (msg_len={})",
            entry.msg.len()
        );
    }
}
