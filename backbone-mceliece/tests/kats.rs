//! KAT validation for Classic McEliece using the official NIST Round 4
//! submission vectors (mceliece-kat-20221023).

use backbone_pqcrypto_internals::kat::FixedRng;

macro_rules! kat_tests {
    ($setup:ident, $keygen:ident, $encaps:ident, $decaps:ident, $sizes:ident, $variant:ident, $name:literal, $params:ident) => {
        fn $setup() -> Vec<std::collections::HashMap<String, Vec<u8>>> {
            use backbone_pqcrypto_internals::kat::parse_kat_file;
            let path = backbone_pqcrypto_internals::kat::kat_dir().join(format!("{}.rsp", $name));
            let kats = parse_kat_file(&path);
            assert!(!kats.is_empty(), "no KAT cases for {}", $name);
            kats
        }

        #[test]
        fn $keygen() {
            use backbone_mceliece::$variant::*;
            for (i, kat) in $setup().iter().enumerate() {
                let seed = kat.get("seed").expect("missing seed");
                let expected_pk = kat.get("pk").expect("missing pk");
                let expected_sk = kat.get("sk").expect("missing sk");
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.clone())).expect("keygen");
                assert_eq!(
                    pk.as_ref(),
                    expected_pk.as_slice(),
                    "{} pk case {}",
                    $name,
                    i
                );
                assert_eq!(
                    sk.as_ref(),
                    expected_sk.as_slice(),
                    "{} sk case {}",
                    $name,
                    i
                );
            }
        }

        #[test]
        fn $encaps() {
            use backbone_mceliece::$variant::*;
            for (i, kat) in $setup().iter().enumerate() {
                let seed = kat.get("seed").expect("missing seed");
                let pk = kat.get("pk").expect("missing pk");
                let expected_ct = kat.get("ct").expect("missing ct");
                let expected_ss = kat.get("ss").expect("missing ss");
                let my_pk = PublicKey::from_bytes(pk).expect("pk");
                let enc =
                    encaps_with_rng(&my_pk, &mut FixedRng::new(seed.clone())).expect("encaps");
                assert_eq!(
                    enc.ciphertext,
                    expected_ct.as_slice(),
                    "{} ct case {}",
                    $name,
                    i
                );
                assert_eq!(
                    enc.shared_secret.as_slice(),
                    expected_ss.as_slice(),
                    "{} ss case {}",
                    $name,
                    i
                );
            }
        }

        #[test]
        fn $decaps() {
            use backbone_mceliece::$variant::*;
            for (i, kat) in $setup().iter().enumerate() {
                let sk = kat.get("sk").expect("missing sk");
                let ct = kat.get("ct").expect("missing ct");
                let ss_expected = kat.get("ss").expect("missing ss");
                let my_sk = SecretKey::from_bytes(sk).unwrap();
                let dec = decaps(&my_sk, ct).expect("decaps");
                assert_eq!(&dec[..], ss_expected.as_slice(), "{} case {}", $name, i);
            }
        }

        #[test]
        fn $sizes() {
            use backbone_mceliece::params::{$params, Params};
            for (i, kat) in $setup().iter().enumerate() {
                assert_eq!(
                    kat.get("pk").expect("pk").len(),
                    <$params as Params>::PK_BYTES,
                    "{} pk size case {}",
                    $name,
                    i
                );
                assert_eq!(
                    kat.get("sk").expect("sk").len(),
                    <$params as Params>::SK_BYTES,
                    "{} sk size case {}",
                    $name,
                    i
                );
                assert_eq!(
                    kat.get("ct").expect("ct").len(),
                    <$params as Params>::CT_BYTES,
                    "{} ct size case {}",
                    $name,
                    i
                );
                assert_eq!(
                    kat.get("ss").expect("ss").len(),
                    <$params as Params>::SS_BYTES,
                    "{} ss size case {}",
                    $name,
                    i
                );
            }
        }
    };
}

kat_tests!(
    kat_348864,
    mceliece348864_kat_keygen,
    mceliece348864_kat_encaps,
    mceliece348864_kat_decaps,
    mceliece348864_kat_key_sizes,
    mceliece348864,
    "mceliece348864",
    McEliece348864Params
);
kat_tests!(
    kat_348864f,
    mceliece348864f_kat_keygen,
    mceliece348864f_kat_encaps,
    mceliece348864f_kat_decaps,
    mceliece348864f_kat_key_sizes,
    mceliece348864f,
    "mceliece348864f",
    McEliece348864fParams
);
kat_tests!(
    kat_460896,
    mceliece460896_kat_keygen,
    mceliece460896_kat_encaps,
    mceliece460896_kat_decaps,
    mceliece460896_kat_key_sizes,
    mceliece460896,
    "mceliece460896",
    McEliece460896Params
);
kat_tests!(
    kat_460896f,
    mceliece460896f_kat_keygen,
    mceliece460896f_kat_encaps,
    mceliece460896f_kat_decaps,
    mceliece460896f_kat_key_sizes,
    mceliece460896f,
    "mceliece460896f",
    McEliece460896fParams
);
kat_tests!(
    kat_6688128,
    mceliece6688128_kat_keygen,
    mceliece6688128_kat_encaps,
    mceliece6688128_kat_decaps,
    mceliece6688128_kat_key_sizes,
    mceliece6688128,
    "mceliece6688128",
    McEliece6688128Params
);
kat_tests!(
    kat_6688128f,
    mceliece6688128f_kat_keygen,
    mceliece6688128f_kat_encaps,
    mceliece6688128f_kat_decaps,
    mceliece6688128f_kat_key_sizes,
    mceliece6688128f,
    "mceliece6688128f",
    McEliece6688128fParams
);
kat_tests!(
    kat_6960119,
    mceliece6960119_kat_keygen,
    mceliece6960119_kat_encaps,
    mceliece6960119_kat_decaps,
    mceliece6960119_kat_key_sizes,
    mceliece6960119,
    "mceliece6960119",
    McEliece6960119Params
);
kat_tests!(
    kat_6960119f,
    mceliece6960119f_kat_keygen,
    mceliece6960119f_kat_encaps,
    mceliece6960119f_kat_decaps,
    mceliece6960119f_kat_key_sizes,
    mceliece6960119f,
    "mceliece6960119f",
    McEliece6960119fParams
);
kat_tests!(
    kat_8192128,
    mceliece8192128_kat_keygen,
    mceliece8192128_kat_encaps,
    mceliece8192128_kat_decaps,
    mceliece8192128_kat_key_sizes,
    mceliece8192128,
    "mceliece8192128",
    McEliece8192128Params
);
kat_tests!(
    kat_8192128f,
    mceliece8192128f_kat_keygen,
    mceliece8192128f_kat_encaps,
    mceliece8192128f_kat_decaps,
    mceliece8192128f_kat_key_sizes,
    mceliece8192128f,
    "mceliece8192128f",
    McEliece8192128fParams
);
