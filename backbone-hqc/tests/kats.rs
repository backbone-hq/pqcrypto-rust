//! HQC Known Answer Tests — vectors generated offline from the official C
//! reference implementation (pqc-hqc, FIPS 207).
//!
//! Seeds match the NIST Round 4 KAT .req sets; pk/sk/ct/ss values are
//! computed by the reference and verified byte-for-byte against this crate.

use backbone_pqcrypto_internals::kat::kat_dir;
use backbone_pqcrypto_internals::kat::parse_kat_file;
use backbone_pqcrypto_internals::kat::FixedRng;

macro_rules! kat_test {
    ($name:ident, $variant:ident, $file:literal) => {
        #[test]
        fn $name() {
            let path = kat_dir().join($file);
            let entries = parse_kat_file(&path);
            assert!(
                !entries.is_empty(),
                "no KAT entries in {file}",
                file = $file
            );
            let mut failures = Vec::new();
            for (i, entry) in entries.iter().enumerate() {
                let seed = entry.get("seed").expect("missing seed");
                let expected_pk = entry.get("pk").expect("missing pk");
                let expected_sk = entry.get("sk").expect("missing sk");
                let expected_ct = entry.get("ct").expect("missing ct");
                let expected_ss = entry.get("ss").expect("missing ss");

                let (pk, sk) =
                    match backbone_hqc::$variant::keygen_with_rng(&mut FixedRng::new(seed.clone()))
                    {
                        Ok(x) => x,
                        Err(e) => {
                            failures.push(format!("entry {i}: keygen failed: {e:?}"));
                            continue;
                        }
                    };
                if pk.as_ref() != expected_pk.as_slice() {
                    failures.push(format!("entry {i}: pk mismatch"));
                    continue;
                }
                if sk.as_ref() != expected_sk.as_slice() {
                    failures.push(format!("entry {i}: sk mismatch"));
                    continue;
                }

                let enc = match backbone_hqc::$variant::encaps_with_rng(
                    &pk,
                    &mut FixedRng::new(seed.clone()),
                ) {
                    Ok(x) => x,
                    Err(e) => {
                        failures.push(format!("entry {i}: encaps failed: {e:?}"));
                        continue;
                    }
                };
                if enc.ciphertext.as_slice() != expected_ct.as_slice() {
                    failures.push(format!("entry {i}: ct mismatch"));
                    continue;
                }
                if enc.shared_secret.as_slice() != expected_ss.as_slice() {
                    failures.push(format!("entry {i}: ss mismatch (encaps)"));
                    continue;
                }

                let dec = match backbone_hqc::$variant::decaps(&sk, &enc.ciphertext) {
                    Ok(x) => x,
                    Err(e) => {
                        failures.push(format!("entry {i}: decaps failed: {e:?}"));
                        continue;
                    }
                };
                if dec.as_slice() != expected_ss.as_slice() {
                    failures.push(format!("entry {i}: ss mismatch (decaps)"));
                }
            }
            if !failures.is_empty() {
                panic!(
                    "{} failures out of {}:\n  {}",
                    failures.len(),
                    entries.len(),
                    failures.join("\n  ")
                );
            }
        }
    };
}

kat_test!(test_hqc1_official_kat, hqc128, "hqc1-keygen.rsp");
kat_test!(test_hqc3_official_kat, hqc192, "hqc3-keygen.rsp");
kat_test!(test_hqc5_official_kat, hqc256, "hqc5-keygen.rsp");
