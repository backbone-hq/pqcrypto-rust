//! KAT validation for Streamlined NTRU Prime against the official NIST
//! submission package (ntruprime-20201007, ntruprime.cr.yp.to).
//!
//! Kept in `src/` (not `tests/`): the encaps leg is white-box on the
//! crate-internal `kem::encaps_with_r_enc`, which the public API does not
//! accept. KeyGen/Encaps/Decaps are verified byte-for-byte vs the .rsp files.

use crate::kem;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use backbone_pqcrypto_internals::kat::kat_dir;
use backbone_pqcrypto_internals::kat::FixedRng;

macro_rules! kat_tests {
    ($setup:ident, $keygen:ident, $encaps:ident, $decaps:ident, $variant:ident, $name:literal, $params:ident) => {
        fn $setup() -> Vec<std::collections::HashMap<String, Vec<u8>>> {
            use backbone_pqcrypto_internals::kat::parse_kat_file;
            let path = kat_dir().join(format!("{}.rsp", $name));
            let kats = parse_kat_file(&path);
            assert!(!kats.is_empty(), "no KAT cases for {}", $name);
            kats
        }

        #[test]
        fn $keygen() {
            for (i, kat) in $setup().iter().enumerate() {
                let seed = kat.get("seed").expect("missing seed");
                let (pk, sk) = crate::$variant::keygen_with_rng(&mut FixedRng::new(seed.clone()))
                    .expect("keygen_with_rng");

                assert_eq!(
                    pk.as_ref(),
                    kat.get("pk").expect("missing pk").as_slice(),
                    "{} pk case {}",
                    $name,
                    i
                );
                assert_eq!(
                    sk.as_ref(),
                    kat.get("sk").expect("missing sk").as_slice(),
                    "{} sk case {}",
                    $name,
                    i
                );
            }
        }

        #[test]
        fn $encaps() {
            use crate::params::$params as ParamsT;
            use crate::params::Params;

            const P: usize = <ParamsT as Params>::P;
            const Q: i16 = <ParamsT as Params>::Q;
            const CT_BYTES: usize = <ParamsT as Params>::CT_BYTES;

            let entries = $setup();

            for (i, kat) in entries.iter().enumerate() {
                let pk = kat.get("pk").expect("missing pk");
                let r_enc = kat.get("r_enc").expect("missing r_enc");
                let (ss, ct) =
                    kem::encaps_with_r_enc::<P, Q>(pk, r_enc, CT_BYTES).expect("encaps_with_r_enc");

                assert_eq!(
                    ct,
                    *kat.get("ct").expect("missing ct"),
                    "{} ct case {}",
                    $name,
                    i
                );
                assert_eq!(
                    ss.as_slice(),
                    kat.get("ss").expect("missing ss").as_slice(),
                    "{} ss case {}",
                    $name,
                    i
                );
            }
        }

        #[test]
        fn $decaps() {
            use crate::$variant::{decaps, SecretKey};

            for (i, kat) in $setup().iter().enumerate() {
                let sk_bytes = kat.get("sk").expect("missing sk");
                let ct = kat.get("ct").expect("missing ct");
                let expected_ss = kat.get("ss").expect("missing ss");

                let sk = SecretKey::from_bytes(sk_bytes).expect("valid sk from KAT");

                let dec_ss = decaps(&sk, ct).expect("decaps failed");
                assert_eq!(
                    dec_ss.as_slice(),
                    expected_ss.as_slice(),
                    "{} ss case {}",
                    $name,
                    i
                );
            }
        }
    };
}

kat_tests!(
    sntrup653_setup,
    sntrup653_kat_keygen,
    sntrup653_kat_encaps,
    sntrup653_kat_decaps,
    sntrup653,
    "sntrup653",
    Sntrup653
);
kat_tests!(
    sntrup761_setup,
    sntrup761_kat_keygen,
    sntrup761_kat_encaps,
    sntrup761_kat_decaps,
    sntrup761,
    "sntrup761",
    Sntrup761
);
kat_tests!(
    sntrup857_setup,
    sntrup857_kat_keygen,
    sntrup857_kat_encaps,
    sntrup857_kat_decaps,
    sntrup857,
    "sntrup857",
    Sntrup857
);
kat_tests!(
    sntrup953_setup,
    sntrup953_kat_keygen,
    sntrup953_kat_encaps,
    sntrup953_kat_decaps,
    sntrup953,
    "sntrup953",
    Sntrup953
);
kat_tests!(
    sntrup1013_setup,
    sntrup1013_kat_keygen,
    sntrup1013_kat_encaps,
    sntrup1013_kat_decaps,
    sntrup1013,
    "sntrup1013",
    Sntrup1013
);
kat_tests!(
    sntrup1277_setup,
    sntrup1277_kat_keygen,
    sntrup1277_kat_encaps,
    sntrup1277_kat_decaps,
    sntrup1277,
    "sntrup1277",
    Sntrup1277
);
