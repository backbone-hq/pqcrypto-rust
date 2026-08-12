//! KAT validation for NTRU LPRime against the official NIST submission
//! package (ntruprime-20201007, ntruprime.cr.yp.to).
//!
//! - KeyGen: 48-byte DRBG seed → (pk, sk), byte-for-byte vs kat_kem.rsp
//! - Encapsulation: r_enc from merged .rsp → (ct, ss)
//! - Decapsulation: (sk, ct) → ss
//!
//! KeyGen (`keygen_with_rng`) and the encaps/decaps legs run through
//! the public variant API; the official harness seeds the DRBG directly.

use backbone_pqcrypto_internals::kat::kat_dir;
use backbone_pqcrypto_internals::kat::parse_kat_file;
use backbone_pqcrypto_internals::kat::FixedRng;
use std::path::Path;

const OFFICIAL_KAT_COUNT: usize = 100;

fn load_kats(rsp_path: &Path) -> Vec<Kat> {
    let entries = parse_kat_file(rsp_path);
    assert_eq!(
        entries.len(),
        OFFICIAL_KAT_COUNT,
        "not enough KAT entries in {}",
        rsp_path.display()
    );
    entries
        .into_iter()
        .map(|entry| Kat {
            seed: entry.get("seed").expect("entry has seed").clone(),
            pk: entry.get("pk").expect("entry has pk").clone(),
            sk: entry.get("sk").expect("entry has sk").clone(),
            ct: entry.get("ct").expect("entry has ct").clone(),
            ss: entry.get("ss").expect("entry has ss").clone(),
            r_enc: entry.get("r_enc").expect("entry has r_enc").clone(),
        })
        .collect()
}

struct Kat {
    seed: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
    r_enc: Vec<u8>,
}

macro_rules! kat_tests {
    ($load:ident, $variant:ident, $crate_variant:ident, $name:literal, $params:ident) => {
        fn $load() -> Vec<Kat> {
            load_kats(&kat_dir().join(concat!($name, ".rsp")))
        }

        #[test]
        fn $variant() {
            use backbone_ntruplr::params::$params as ParamsT;
            use backbone_ntruplr::params::Params;

            const PK_BYTES: usize = <ParamsT as Params>::PK_BYTES;
            const SK_BYTES: usize = <ParamsT as Params>::SK_BYTES;

            let kats = $load();
            assert_eq!(kats.len(), OFFICIAL_KAT_COUNT, "{} KAT count", $name);

            for (i, kat) in kats.iter().enumerate() {
                assert_eq!(kat.pk.len(), PK_BYTES, "{} entry {i}: pk size", $name);
                assert_eq!(kat.sk.len(), SK_BYTES, "{} entry {i}: sk size", $name);
                assert_eq!(kat.r_enc.len(), 32, "{} entry {i}: r size", $name);

                let (pk, sk) = backbone_ntruplr::$crate_variant::keygen_with_rng(
                    &mut FixedRng::new(kat.seed.clone()),
                )
                .expect("keygen_with_rng");

                assert_eq!(
                    pk.as_ref(),
                    kat.pk.as_slice(),
                    "{} entry {i}: pk mismatch",
                    $name
                );
                assert_eq!(
                    sk.as_ref(),
                    kat.sk.as_slice(),
                    "{} entry {i}: sk mismatch",
                    $name
                );
            }
        }
    };
}

macro_rules! kat_op_tests {
    ($load:ident, $variant:ident, $crate_variant:ident, $name:literal, $params:ident) => {
        fn $load() -> Vec<Kat> {
            load_kats(&kat_dir().join(concat!($name, ".rsp")))
        }

        #[test]
        fn $variant() {
            use backbone_ntruplr::params::$params as ParamsT;
            use backbone_ntruplr::params::Params;
            use backbone_ntruplr::$crate_variant::{decaps, encaps_with_rng, PublicKey, SecretKey};

            const PK_BYTES: usize = <ParamsT as Params>::PK_BYTES;
            const SK_BYTES: usize = <ParamsT as Params>::SK_BYTES;

            let kats = $load();
            assert_eq!(kats.len(), OFFICIAL_KAT_COUNT, "{} KAT count", $name);

            for (i, kat) in kats.iter().enumerate() {
                assert_eq!(kat.pk.len(), PK_BYTES, "{} entry {i}: pk size", $name);
                assert_eq!(kat.sk.len(), SK_BYTES, "{} entry {i}: sk size", $name);
                assert_eq!(kat.r_enc.len(), 32, "{} entry {i}: r size", $name);

                let pk = PublicKey::from_bytes(&kat.pk).expect("valid pk from KAT");
                let enc =
                    encaps_with_rng(&pk, &mut FixedRng::new(kat.r_enc.clone())).expect("encaps");
                assert_eq!(enc.ciphertext, kat.ct, "{} entry {i}: ct mismatch", $name);
                assert_eq!(
                    enc.shared_secret.as_slice(),
                    kat.ss.as_slice(),
                    "{} entry {i}: ss mismatch",
                    $name
                );

                let sk = SecretKey::from_bytes(&kat.sk).expect("valid sk from KAT");
                let dec_ss = decaps(&sk, &kat.ct).expect("decaps");
                assert_eq!(
                    dec_ss.as_slice(),
                    kat.ss.as_slice(),
                    "{} entry {i}: decaps ss mismatch",
                    $name
                );
            }
        }
    };
}

kat_tests!(
    load_653,
    ntruplr653_kat_keygen,
    ntruplr653,
    "ntrulpr653",
    Ntruplr653
);
kat_tests!(
    load_761,
    ntruplr761_kat_keygen,
    ntruplr761,
    "ntrulpr761",
    Ntruplr761
);
kat_tests!(
    load_857,
    ntruplr857_kat_keygen,
    ntruplr857,
    "ntrulpr857",
    Ntruplr857
);
kat_tests!(
    load_953,
    ntruplr953_kat_keygen,
    ntruplr953,
    "ntrulpr953",
    Ntruplr953
);
kat_tests!(
    load_1013,
    ntruplr1013_kat_keygen,
    ntruplr1013,
    "ntrulpr1013",
    Ntruplr1013
);
kat_tests!(
    load_1277,
    ntruplr1277_kat_keygen,
    ntruplr1277,
    "ntrulpr1277",
    Ntruplr1277
);
kat_op_tests!(
    load_653_ops,
    ntruplr653_kat_encaps_decaps,
    ntruplr653,
    "ntrulpr653",
    Ntruplr653
);
kat_op_tests!(
    load_761_ops,
    ntruplr761_kat_encaps_decaps,
    ntruplr761,
    "ntrulpr761",
    Ntruplr761
);
kat_op_tests!(
    load_857_ops,
    ntruplr857_kat_encaps_decaps,
    ntruplr857,
    "ntrulpr857",
    Ntruplr857
);
kat_op_tests!(
    load_953_ops,
    ntruplr953_kat_encaps_decaps,
    ntruplr953,
    "ntrulpr953",
    Ntruplr953
);
kat_op_tests!(
    load_1013_ops,
    ntruplr1013_kat_encaps_decaps,
    ntruplr1013,
    "ntrulpr1013",
    Ntruplr1013
);
kat_op_tests!(
    load_1277_ops,
    ntruplr1277_kat_encaps_decaps,
    ntruplr1277,
    "ntrulpr1277",
    Ntruplr1277
);
