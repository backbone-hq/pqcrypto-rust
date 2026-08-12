//! KAT validation for ML-DSA (FIPS 204) using NIST ACVP vectors: KeyGen,
//! Sign, and Verify against every entry of the `mldsaNN-pure.rsp` files
//! (100 entries per variant). Roundtrips live in `roundtrip.rs`.
#![allow(clippy::std_instead_of_alloc)]

use backbone_ml_dsa::mldsa44;
use backbone_ml_dsa::mldsa65;
use backbone_ml_dsa::mldsa87;
use backbone_ml_dsa::params::{Mldsa44, Mldsa65, Mldsa87, Params};
use backbone_pqcrypto_internals::kat::kat_dir;
use backbone_pqcrypto_internals::kat::FixedRng;
use std::collections::HashMap;

#[allow(dead_code)]
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
    backbone_pqcrypto_internals::kat::parse_kat_file(path)
        .into_iter()
        .map(map_to_entry)
        .collect()
}

fn kat_path(name: &str) -> String {
    kat_dir().join(format!("{name}.rsp")).display().to_string()
}

#[test]
fn test_ml_dsa_44_keygen_kat() {
    let entries = get_kat_entries(&kat_path("mldsa44-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (pk, sk) = mldsa44::keygen_with_rng(&mut FixedRng::new(entry.seed.clone())).unwrap();
        // PK and SK must match the ACVP reference byte-for-byte.
        // NOTE: the `sk` fields in these .rsp files are stored in the FIPS 204
        // spec encoding (BitPack: s1/s2 as eta-coeff, t0 as 2^12-t0). The key
        // values are the NIST ACVP reference's; only the byte representation
        // differs from the raw bundle export (which used the legacy flipped
        // convention: s1/s2 as coeff+eta, t0 as two's complement).
        assert_eq!(pk.pk, entry.pk, "KAT entry {i}: pk mismatch");
        assert_eq!(
            sk.as_ref(),
            entry.sk.as_slice(),
            "KAT entry {i}: sk mismatch"
        );
    }
}

#[test]
fn test_ml_dsa_65_keygen_kat() {
    let entries = get_kat_entries(&kat_path("mldsa65-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (pk, sk) = mldsa65::keygen_with_rng(&mut FixedRng::new(entry.seed.clone())).unwrap();
        // PK and SK must match the ACVP reference byte-for-byte (see note in the 44 test).
        assert_eq!(pk.pk, entry.pk, "KAT entry {i}: pk mismatch");
        assert_eq!(
            sk.as_ref(),
            entry.sk.as_slice(),
            "KAT entry {i}: sk mismatch"
        );
    }
}

#[test]
fn test_ml_dsa_87_keygen_kat() {
    let entries = get_kat_entries(&kat_path("mldsa87-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (pk, sk) = mldsa87::keygen_with_rng(&mut FixedRng::new(entry.seed.clone())).unwrap();
        // PK and SK must match the ACVP reference byte-for-byte (see note in the 44 test).
        assert_eq!(pk.pk, entry.pk, "KAT entry {i}: pk mismatch");
        assert_eq!(
            sk.as_ref(),
            entry.sk.as_slice(),
            "KAT entry {i}: sk mismatch"
        );
    }
}

#[test]
fn test_ml_dsa_44_sign_output_kat() {
    let entries = get_kat_entries(&kat_path("mldsa44-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (_pk, sk) = mldsa44::keygen_with_rng(&mut FixedRng::new(entry.seed.clone())).unwrap();
        let sm = &entry.sm;
        let sig_expected = &sm[..Mldsa44::SIG_BYTES];
        let sig = mldsa44::sign_with_rng(
            &sk,
            &entry.msg,
            &mut FixedRng::new(vec![0u8; 32]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(sig.sig, sig_expected, "KAT entry {i}: sign output mismatch");
    }
}

#[test]
fn test_ml_dsa_65_sign_output_kat() {
    let entries = get_kat_entries(&kat_path("mldsa65-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (_pk, sk) = mldsa65::keygen_with_rng(&mut FixedRng::new(entry.seed.clone())).unwrap();
        let sm = &entry.sm;
        let sig_expected = &sm[..Mldsa65::SIG_BYTES];
        let sig = mldsa65::sign_with_rng(
            &sk,
            &entry.msg,
            &mut FixedRng::new(vec![0u8; 32]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(sig.sig, sig_expected, "KAT entry {i}: sign output mismatch");
    }
}

#[test]
fn test_ml_dsa_87_sign_output_kat() {
    let entries = get_kat_entries(&kat_path("mldsa87-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let (_pk, sk) = mldsa87::keygen_with_rng(&mut FixedRng::new(entry.seed.clone())).unwrap();
        let sm = &entry.sm;
        let sig_expected = &sm[..Mldsa87::SIG_BYTES];
        let sig = mldsa87::sign_with_rng(
            &sk,
            &entry.msg,
            &mut FixedRng::new(vec![0u8; 32]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(sig.sig, sig_expected, "KAT entry {i}: sign output mismatch");
    }
}

#[test]
fn test_ml_dsa_44_verify_kat() {
    let entries = get_kat_entries(&kat_path("mldsa44-pure"));
    assert!(!entries.is_empty(), "No KAT entries found");
    for (i, entry) in entries.iter().enumerate() {
        let pk = mldsa44::PublicKey {
            pk: entry.pk.clone(),
        };
        let sig = mldsa44::Signature {
            sig: entry.sm[..Mldsa44::SIG_BYTES].to_vec(),
        };
        assert!(
            mldsa44::verify(&pk, &entry.msg, &sig, None, None).is_ok(),
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
            sig: entry.sm[..Mldsa65::SIG_BYTES].to_vec(),
        };
        assert!(
            mldsa65::verify(&pk, &entry.msg, &sig, None, None).is_ok(),
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
            sig: entry.sm[..Mldsa87::SIG_BYTES].to_vec(),
        };
        assert!(
            mldsa87::verify(&pk, &entry.msg, &sig, None, None).is_ok(),
            "KAT entry {i}: KAT signature fails verify (msg_len={})",
            entry.msg.len()
        );
    }
}
