//! HQC Known Answer Tests using the official reference `.rsp` files.

use std::collections::HashMap;
use std::path::PathBuf;

use backbone_hqc::{hqc128, hqc192, hqc256};
use backbone_pqcrypto_internals::kat::hex_decode;

fn kat_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn parse_kat_file(path: &str) -> Vec<HashMap<String, Vec<u8>>> {
    let content = std::fs::read_to_string(path).expect("failed to read KAT file");
    let mut entries = Vec::new();
    let mut current: HashMap<String, Vec<u8>> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(" = ") {
            if key == "count" {
                if !current.is_empty() {
                    entries.push(core::mem::take(&mut current));
                }
            } else {
                current.insert(key.to_string(), hex_decode(value));
            }
        }
    }
    if !current.is_empty() {
        entries.push(current);
    }
    entries
}

fn first_entry(kat_file: &str) -> HashMap<String, Vec<u8>> {
    let mut path = kat_dir();
    path.push(kat_file);
    let entries = parse_kat_file(path.to_str().expect("KAT path is valid UTF-8"));
    assert!(!entries.is_empty(), "no KAT entries found in {kat_file}");
    entries.into_iter().next().expect("entry exists")
}

#[test]
fn test_hqc1_official_kat() {
    let entry = first_entry("hqc1-KAT.rsp");
    let seed = entry.get("seed").expect("missing seed");
    let expected_pk = entry.get("pk").expect("missing pk");
    let expected_sk = entry.get("sk").expect("missing sk");
    let expected_ct = entry.get("ct").expect("missing ct");
    let expected_ss = entry.get("ss").expect("missing ss");

    let (pk, sk) = hqc128::keygen(seed).expect("keygen");
    assert_eq!(pk.as_ref(), expected_pk.as_slice());
    assert_eq!(sk.as_ref(), expected_sk.as_slice());

    let enc = hqc128::encaps_deterministic(&pk, seed).expect("encaps");
    assert_eq!(enc.ciphertext.as_slice(), expected_ct.as_slice());
    assert_eq!(enc.shared_secret.as_slice(), expected_ss.as_slice());

    let dec = hqc128::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(dec.as_slice(), expected_ss.as_slice());
}

#[test]
fn test_hqc3_official_kat() {
    let entry = first_entry("hqc3-KAT.rsp");
    let seed = entry.get("seed").expect("missing seed");
    let expected_pk = entry.get("pk").expect("missing pk");
    let expected_sk = entry.get("sk").expect("missing sk");
    let expected_ct = entry.get("ct").expect("missing ct");
    let expected_ss = entry.get("ss").expect("missing ss");

    let (pk, sk) = hqc192::keygen(seed).expect("keygen");
    assert_eq!(pk.as_ref(), expected_pk.as_slice());
    assert_eq!(sk.as_ref(), expected_sk.as_slice());

    let enc = hqc192::encaps_deterministic(&pk, seed).expect("encaps");
    assert_eq!(enc.ciphertext.as_slice(), expected_ct.as_slice());
    assert_eq!(enc.shared_secret.as_slice(), expected_ss.as_slice());

    let dec = hqc192::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(dec.as_slice(), expected_ss.as_slice());
}

#[test]
fn test_hqc5_official_kat() {
    let entry = first_entry("hqc5-KAT.rsp");
    let seed = entry.get("seed").expect("missing seed");
    let expected_pk = entry.get("pk").expect("missing pk");
    let expected_sk = entry.get("sk").expect("missing sk");
    let expected_ct = entry.get("ct").expect("missing ct");
    let expected_ss = entry.get("ss").expect("missing ss");

    let (pk, sk) = hqc256::keygen(seed).expect("keygen");
    assert_eq!(pk.as_ref(), expected_pk.as_slice());
    assert_eq!(sk.as_ref(), expected_sk.as_slice());

    let enc = hqc256::encaps_deterministic(&pk, seed).expect("encaps");
    assert_eq!(enc.ciphertext.as_slice(), expected_ct.as_slice());
    assert_eq!(enc.shared_secret.as_slice(), expected_ss.as_slice());

    let dec = hqc256::decaps(&sk, &enc.ciphertext).expect("decaps");
    assert_eq!(dec.as_slice(), expected_ss.as_slice());
}
