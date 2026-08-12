//! KAT validation for ML-KEM (FIPS 203) using NIST ACVP vectors.
//!
//! Kept in `src/` (not `tests/`) because the key-check legs use the
//! crate-internal `kem::check_public_key` / `kem::check_secret_key`
//! canonical-encoding validators, which the public API does not expose.
//!
//! KeyGen: (d, z) → (ek, dk) · Encaps: (ek, m) → (c, K') · Decaps: (dk, c) → k

use crate::kem;
use alloc::format;
use backbone_pqcrypto_internals::kat::kat_dir;
use backbone_pqcrypto_internals::kat::parse_kat_file;
use backbone_pqcrypto_internals::kat::FixedRng;

fn rsp_path(name: &str) -> std::path::PathBuf {
    kat_dir().join(format!("{name}.rsp"))
}

macro_rules! kem_tests {
    ($variant:ident, $keygen_file:literal, $encaps_file:literal, $decaps_file:literal, $keycheck_file:literal, $keygen:ident, $encaps:ident, $decaps:ident, $keycheck:ident, $k_val:expr, $pk_bytes:expr, $du:expr, $dv:expr, $eta1:expr, $eta2:expr) => {
        #[test]
        fn $keygen() {
            let path = rsp_path($keygen_file);
            let entries = parse_kat_file(&path);
            assert!(!entries.is_empty(), "no keygen entries in {}", $keygen_file);

            for (i, entry) in entries.iter().enumerate() {
                let d: &[u8] = entry.get("d").expect("missing d");
                let z: &[u8] = entry.get("z").expect("missing z");
                let expected_ek = entry.get("ek").expect("missing ek");
                let expected_dk = entry.get("dk").expect("missing dk");

                let d_arr: [u8; 32] = d.try_into().expect("d must be 32 bytes");
                let z_arr: [u8; 32] = z.try_into().expect("z must be 32 bytes");

                let (pk, sk) = crate::$variant::keygen_with_rng(&mut FixedRng::new(
                    [d_arr.as_slice(), z_arr.as_slice()].concat(),
                ))
                .expect("keygen");

                assert_eq!(
                    pk.pk,
                    expected_ek.as_slice(),
                    "{} entry {i}: ek mismatch",
                    $keygen_file
                );
                assert_eq!(
                    sk.as_ref(),
                    expected_dk.as_slice(),
                    "{} entry {i}: dk mismatch",
                    $keygen_file
                );
            }
        }

        #[test]
        fn $encaps() {
            use crate::$variant::encaps_with_rng;

            let path = rsp_path($encaps_file);
            let entries = parse_kat_file(&path);
            assert!(!entries.is_empty(), "no encaps entries in {}", $encaps_file);

            for (i, entry) in entries.iter().enumerate() {
                let ek = entry.get("ek").expect("missing ek");
                let m = entry.get("m").expect("missing m");
                let expected_ct = entry.get("c").expect("missing c");
                let expected_kprime = entry.get("k").expect("missing k");

                let pk = crate::$variant::PublicKey::from_bytes(ek).expect("valid ek from KAT");

                let enc =
                    encaps_with_rng(&pk, &mut FixedRng::new(m.to_vec())).expect("encaps failed");

                assert_eq!(
                    enc.ciphertext, *expected_ct,
                    "{} entry {i}: ct mismatch\nciphertext must match expected",
                    $encaps_file
                );

                assert_eq!(
                    enc.shared_secret.as_slice(),
                    expected_kprime.as_slice(),
                    "{} entry {i}: returned shared secret must match ACVP k",
                    $encaps_file
                );
            }
        }

        #[test]
        fn $decaps() {
            let path = rsp_path($decaps_file);
            let entries = parse_kat_file(&path);
            assert!(!entries.is_empty(), "no decaps entries in {}", $decaps_file);

            for (i, entry) in entries.iter().enumerate() {
                let dk = entry.get("dk").expect("missing dk");
                let ct = entry.get("c").expect("missing c");
                let expected_k = entry.get("k").expect("missing k");

                // Assert the PUBLIC decaps API returns the NIST-vector shared
                // secret. The ACVP .rsp `k` field encodes the correct per-branch
                // expectation: K' for valid ciphertexts, J(z||c) for invalid ones.
                let sk = crate::$variant::SecretKey::from_bytes(dk).expect("valid dk from KAT");
                let ss = crate::$variant::decaps(&sk, ct).expect("decaps must succeed");
                assert_eq!(
                    ss.as_slice(),
                    expected_k.as_slice(),
                    "{} entry {i}: decaps shared secret must match ACVP k",
                    $decaps_file
                );
            }
        }

        #[test]
        fn $keycheck() {
            let path = rsp_path($keycheck_file);
            let entries = parse_kat_file(&path);
            assert!(
                !entries.is_empty(),
                "no keycheck entries in {}",
                $keycheck_file
            );

            for (i, entry) in entries.iter().enumerate() {
                if let Some(ek) = entry.get("ek") {
                    let valid = kem::check_public_key::<$k_val>(ek);
                    let expected = entry.get("testPassed").expect("missing testPassed");
                    let should_pass = expected.first() == Some(&b't');
                    assert_eq!(
                        valid, should_pass,
                        "{} entry {i}: encaps key check mismatch",
                        $keycheck_file
                    );
                } else if let Some(dk) = entry.get("dk") {
                    let valid = kem::check_secret_key::<$k_val>(dk, $pk_bytes);
                    let expected = entry.get("testPassed").expect("missing testPassed");
                    let should_pass = expected.first() == Some(&b't');
                    assert_eq!(
                        valid, should_pass,
                        "{} entry {i}: decaps key check mismatch",
                        $keycheck_file
                    );
                }
            }
        }
    };
}

kem_tests!(
    mlkem512,
    "mlkem512-keygen",
    "mlkem512-encaps",
    "mlkem512-decaps",
    "mlkem512-keycheck",
    mlkem512_kat_keygen,
    mlkem512_kat_encaps,
    mlkem512_kat_decaps,
    mlkem512_kat_keycheck,
    2,
    800, // PK_BYTES
    10,  // du
    4,   // dv
    3,   // eta1
    2    // eta2
);
kem_tests!(
    mlkem768,
    "mlkem768-keygen",
    "mlkem768-encaps",
    "mlkem768-decaps",
    "mlkem768-keycheck",
    mlkem768_kat_keygen,
    mlkem768_kat_encaps,
    mlkem768_kat_decaps,
    mlkem768_kat_keycheck,
    3,
    1184, // PK_BYTES
    10,   // du
    4,    // dv
    2,    // eta1
    2     // eta2
);
kem_tests!(
    mlkem1024,
    "mlkem1024-keygen",
    "mlkem1024-encaps",
    "mlkem1024-decaps",
    "mlkem1024-keycheck",
    mlkem1024_kat_keygen,
    mlkem1024_kat_encaps,
    mlkem1024_kat_decaps,
    mlkem1024_kat_keycheck,
    4,
    1568, // PK_BYTES
    11,   // du
    5,    // dv
    2,    // eta1
    2     // eta2
);
