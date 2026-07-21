//! KAT-style tests for NTRU LPRime.

use std::path::PathBuf;

use pqcrypto_ntruplr::params::{Ntruplr653, Ntruplr761, Params};
use pqcrypto_ntruplr::{ntruplr653, ntruplr761};

fn kat_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("kats")
}
const OFFICIAL_KAT_COUNT: usize = 100;

#[test]
fn ntruplr_sizes_match_reference() {
    assert_eq!(<Ntruplr653 as Params>::PK_BYTES, 897);
    assert_eq!(<Ntruplr653 as Params>::SK_BYTES, 1125);
    assert_eq!(<Ntruplr653 as Params>::CT_BYTES, 1025);
    assert_eq!(<Ntruplr653 as Params>::SS_BYTES, 32);

    assert_eq!(<Ntruplr761 as Params>::PK_BYTES, 1039);
    assert_eq!(<Ntruplr761 as Params>::SK_BYTES, 1294);
    assert_eq!(<Ntruplr761 as Params>::CT_BYTES, 1167);
    assert_eq!(<Ntruplr761 as Params>::SS_BYTES, 32);
}

#[test]
fn ntruplr653_roundtrip_and_determinism() {
    let r_seed = [0x42u8; 32];

    for count in 0..5 {
        let mut seed = [0u8; 48];
        seed[..8].copy_from_slice(&[0x00, 0x01, 0x02, 0x03, 0, 0, 0, count]);

        let (pk, sk) = ntruplr653::keypair_from_seed(&seed).expect("keygen should succeed");
        assert_eq!(pk.pk.len(), <Ntruplr653 as Params>::PK_BYTES);
        assert_eq!(sk.as_ref().len(), <Ntruplr653 as Params>::SK_BYTES);
        assert!(!pk.pk.iter().all(|&b| b == 0));

        let enc = ntruplr653::encaps_deterministic(&pk, &r_seed).expect("encaps should succeed");
        assert_eq!(enc.ciphertext.len(), <Ntruplr653 as Params>::CT_BYTES);

        let ss_dec = ntruplr653::decaps(&sk, &enc.ciphertext).expect("decaps should succeed");
        assert_eq!(enc.shared_secret, ss_dec, "ss mismatch at count {count}");

        let enc2 =
            ntruplr653::encaps_deterministic(&pk, &r_seed).expect("encaps should be deterministic");
        assert_eq!(enc.ciphertext, enc2.ciphertext);
        assert_eq!(enc.shared_secret, enc2.shared_secret);
    }
}

#[test]
fn ntruplr761_roundtrip_and_determinism() {
    let r_seed = [0x42u8; 32];

    for count in 0..5 {
        let mut seed = [0u8; 48];
        seed[..8].copy_from_slice(&[0x00, 0x01, 0x02, 0x03, 0, 0, 0, count]);

        let (pk, sk) = ntruplr761::keypair_from_seed(&seed).expect("keygen should succeed");
        assert_eq!(pk.pk.len(), <Ntruplr761 as Params>::PK_BYTES);
        assert_eq!(sk.as_ref().len(), <Ntruplr761 as Params>::SK_BYTES);
        assert!(!pk.pk.iter().all(|&b| b == 0));

        let enc = ntruplr761::encaps_deterministic(&pk, &r_seed).expect("encaps should succeed");
        assert_eq!(enc.ciphertext.len(), <Ntruplr761 as Params>::CT_BYTES);

        let ss_dec = ntruplr761::decaps(&sk, &enc.ciphertext).expect("decaps should succeed");
        assert_eq!(enc.shared_secret, ss_dec, "ss mismatch at count {count}");

        let enc2 =
            ntruplr761::encaps_deterministic(&pk, &r_seed).expect("encaps should be deterministic");
        assert_eq!(enc.ciphertext, enc2.ciphertext);
        assert_eq!(enc.shared_secret, enc2.shared_secret);
    }
}

#[test]
fn official_reference_kats_when_available() {
    official_ntruplr653_kats();
    official_ntruplr761_kats();
}

fn official_ntruplr653_kats() {
    let rsp_path = kat_dir().join("ntrulpr653.rsp");
    let int_path = kat_dir().join("ntrulpr653.int");
    let Some(kats) = load_kats(
        rsp_path.to_str().expect("UTF-8 path"),
        int_path.to_str().expect("UTF-8 path"),
        OFFICIAL_KAT_COUNT,
    ) else {
        return;
    };

    for kat in kats {
        assert_eq!(kat.pk.len(), <Ntruplr653 as Params>::PK_BYTES);
        assert_eq!(kat.sk.len(), <Ntruplr653 as Params>::SK_BYTES);
        assert_eq!(kat.ct.len(), <Ntruplr653 as Params>::CT_BYTES);
        assert_eq!(kat.ss.len(), <Ntruplr653 as Params>::SS_BYTES);
        assert_eq!(kat.r_enc.len(), 32);

        let pk = ntruplr653::PublicKey { pk: kat.pk };
        let sk = ntruplr653::SecretKey::from_bytes(&kat.sk).expect("valid secret key from KAT");

        let enc = ntruplr653::encaps_deterministic(&pk, &kat.r_enc).expect("encaps should succeed");
        assert_eq!(enc.ciphertext, kat.ct);
        assert_eq!(enc.shared_secret.as_slice(), kat.ss.as_slice());

        let ss_dec = ntruplr653::decaps(&sk, &kat.ct).expect("decaps should succeed");
        assert_eq!(ss_dec.as_slice(), kat.ss.as_slice());
    }
}

fn official_ntruplr761_kats() {
    let rsp_path = kat_dir().join("ntrulpr761.rsp");
    let int_path = kat_dir().join("ntrulpr761.int");
    let Some(kats) = load_kats(
        rsp_path.to_str().expect("UTF-8 path"),
        int_path.to_str().expect("UTF-8 path"),
        OFFICIAL_KAT_COUNT,
    ) else {
        return;
    };

    for kat in kats {
        assert_eq!(kat.pk.len(), <Ntruplr761 as Params>::PK_BYTES);
        assert_eq!(kat.sk.len(), <Ntruplr761 as Params>::SK_BYTES);
        assert_eq!(kat.ct.len(), <Ntruplr761 as Params>::CT_BYTES);
        assert_eq!(kat.ss.len(), <Ntruplr761 as Params>::SS_BYTES);
        assert_eq!(kat.r_enc.len(), 32);

        let pk = ntruplr761::PublicKey { pk: kat.pk };
        let sk = ntruplr761::SecretKey::from_bytes(&kat.sk).expect("valid secret key from KAT");

        let enc = ntruplr761::encaps_deterministic(&pk, &kat.r_enc).expect("encaps should succeed");
        assert_eq!(enc.ciphertext, kat.ct);
        assert_eq!(enc.shared_secret.as_slice(), kat.ss.as_slice());

        let ss_dec = ntruplr761::decaps(&sk, &kat.ct).expect("decaps should succeed");
        assert_eq!(ss_dec.as_slice(), kat.ss.as_slice());
    }
}

#[derive(Debug)]
struct Kat {
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
    r_enc: Vec<u8>,
}

fn load_kats(rsp_path: &str, int_path: &str, limit: usize) -> Option<Vec<Kat>> {
    let contents = match std::fs::read_to_string(rsp_path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => panic!("failed to read {rsp_path}: {err}"),
    };
    let r_encs = load_r_encs(int_path, limit)?;

    let mut kats = Vec::new();
    let mut pk = None;
    let mut sk = None;
    let mut ct = None;

    for line in contents.lines() {
        if let Some(hex) = line.strip_prefix("pk = ") {
            pk = Some(hex_to_bytes(hex));
        } else if let Some(hex) = line.strip_prefix("sk = ") {
            sk = Some(hex_to_bytes(hex));
        } else if let Some(hex) = line.strip_prefix("ct = ") {
            ct = Some(hex_to_bytes(hex));
        } else if let Some(hex) = line.strip_prefix("ss = ") {
            kats.push(Kat {
                pk: pk.take().expect("pk appears before ss"),
                sk: sk.take().expect("sk appears before ss"),
                ct: ct.take().expect("ct appears before ss"),
                ss: hex_to_bytes(hex),
                r_enc: r_encs[kats.len()].clone(),
            });

            if kats.len() == limit {
                break;
            }
        }
    }

    assert_eq!(kats.len(), limit, "not enough KAT entries in {rsp_path}");
    Some(kats)
}

fn load_r_encs(path: &str, limit: usize) -> Option<Vec<Vec<u8>>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => panic!("failed to read {path}: {err}"),
    };

    let mut out = Vec::new();
    let mut seen = 0usize;
    for line in contents.lines() {
        if let Some(hex) = line.strip_prefix("Hide r_enc: ") {
            if seen.is_multiple_of(2) {
                out.push(hex_to_bytes(hex));
                if out.len() == limit {
                    break;
                }
            }
            seen += 1;
        }
    }

    assert_eq!(out.len(), limit, "not enough r_enc entries in {path}");
    Some(out)
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex length must be even");
    hex.as_bytes()
        .chunks_exact(2)
        .map(|chunk| (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]))
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte {byte}"),
    }
}
