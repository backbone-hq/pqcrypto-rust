//! KAT validation tests for McEliece variants.
macro_rules! kat_tests {
    ($variant:ident, $name:literal, $params:ident) => {
        mod $variant {
            use backbone_mceliece::params::{$params, Params};
            use backbone_mceliece::$variant::*;
            use backbone_pqcrypto_internals::kat::parse_kat_file;
            use std::path::PathBuf;

            #[test]
            fn kat_decaps() {
                let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                let path = manifest.join(format!("tests/kats/{}.rsp", $name));
                let kats = parse_kat_file(path.to_str().unwrap());
                assert!(!kats.is_empty(), "no KAT cases for {}", $name);

                for (i, kat) in kats.iter().enumerate() {
                    let pk = kat.get("pk").expect("missing pk");
                    let sk = kat.get("sk").expect("missing sk");
                    let ct = kat.get("ct").expect("missing ct");
                    let ss_expected = kat.get("ss").expect("missing ss");

                    assert_eq!(
                        pk.len(),
                        <$params as Params>::PK_BYTES,
                        "{} pk size case {}",
                        $name,
                        i
                    );
                    assert_eq!(
                        sk.len(),
                        <$params as Params>::SK_BYTES,
                        "{} sk size case {}",
                        $name,
                        i
                    );
                    assert_eq!(
                        ct.len(),
                        <$params as Params>::CT_BYTES,
                        "{} ct size case {}",
                        $name,
                        i
                    );
                    assert_eq!(
                        ss_expected.len(),
                        <$params as Params>::SS_BYTES,
                        "{} ss size case {}",
                        $name,
                        i
                    );

                    let my_sk = SecretKey::from_bytes(sk).unwrap();
                    let dec = decaps(&my_sk, ct).expect("decaps");
                    assert_eq!(&dec[..], ss_expected.as_slice(), "{} case {}", $name, i);
                }
            }

            #[test]
            fn kat_public_key_encaps_roundtrips() {
                let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                let path = manifest.join(format!("tests/kats/{}.rsp", $name));
                let kats = parse_kat_file(path.to_str().unwrap());
                assert!(!kats.is_empty(), "no KAT cases for {}", $name);

                for (i, kat) in kats.iter().enumerate() {
                    let pk = kat.get("pk").expect("missing pk");
                    let sk = kat.get("sk").expect("missing sk");
                    let my_pk = PublicKey { pk: pk.to_vec() };
                    let my_sk = SecretKey::from_bytes(sk).unwrap();
                    let mut seed = [0u8; 32];
                    seed[0] = u8::try_from(i).expect("i is < 256 in KAT tests");

                    let enc = encaps_deterministic(&my_pk, &seed).expect("encaps");
                    assert_eq!(
                        enc.ciphertext.len(),
                        <$params as Params>::CT_BYTES,
                        "{} ct size case {}",
                        $name,
                        i
                    );
                    let dec = decaps(&my_sk, &enc.ciphertext).expect("decaps generated ct");
                    assert_eq!(
                        dec, enc.shared_secret,
                        "{} generated roundtrip case {}",
                        $name, i
                    );
                }
            }
        }
    };
}

kat_tests!(mceliece348864, "mceliece348864", McEliece348864Params);
kat_tests!(mceliece348864f, "mceliece348864f", McEliece348864fParams);
kat_tests!(mceliece460896, "mceliece460896", McEliece460896Params);
kat_tests!(mceliece460896f, "mceliece460896f", McEliece460896fParams);
kat_tests!(mceliece6688128, "mceliece6688128", McEliece6688128Params);
kat_tests!(mceliece6688128f, "mceliece6688128f", McEliece6688128fParams);
kat_tests!(mceliece6960119, "mceliece6960119", McEliece6960119Params);
kat_tests!(mceliece6960119f, "mceliece6960119f", McEliece6960119fParams);
kat_tests!(mceliece8192128, "mceliece8192128", McEliece8192128Params);
kat_tests!(mceliece8192128f, "mceliece8192128f", McEliece8192128fParams);
