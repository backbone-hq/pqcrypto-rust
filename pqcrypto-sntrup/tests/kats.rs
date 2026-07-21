//! KAT validation tests for Streamlined NTRU Prime.

use std::path::PathBuf;

fn kat_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("kats")
}

macro_rules! kat_tests {
    ($variant:ident, $variant_name:literal) => {
        mod $variant {
            use pqcrypto_sntrup::$variant::{decaps, SecretKey};

            #[test]
            fn decaps_kat() {
                let path = super::kat_dir().join(concat!($variant_name, ".rsp"));
                let entries = pqcrypto_utils::kat::parse_kat_file(path.to_str().unwrap());
                assert!(!entries.is_empty(), "no KAT entries for {}", $variant_name);

                for (i, entry) in entries.iter().enumerate() {
                    let sk_bytes = entry.get("sk").expect("missing sk");
                    let ct = entry.get("ct").expect("missing ct");
                    let expected_ss = entry.get("ss").expect("missing ss");

                    let sk = SecretKey::from_bytes(sk_bytes).expect("valid sk from KAT");

                    let dec_ss = decaps(&sk, ct).expect("decaps failed");
                    assert_eq!(
                        dec_ss.as_slice(),
                        expected_ss.as_slice(),
                        "{} entry {}: ss mismatch",
                        $variant_name,
                        i
                    );
                }
            }
        }
    };
}

kat_tests!(sntrup653, "sntrup653");
kat_tests!(sntrup761, "sntrup761");
kat_tests!(sntrup857, "sntrup857");
