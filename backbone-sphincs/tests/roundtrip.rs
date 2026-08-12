//! Roundtrip tests for all SLH-DSA (SPHINCS+, FIPS 205) variants: pure-mode
//! sign → verify, Hash-SLH-DSA (pre-hash) sign → verify, and the C1
//! regression that pure mode formats M' = 0x00 ‖ ctx_len ‖ ctx (empty
//! context: 0x00 ‖ 0x00) — byte-identical to the context path, the only
//! oracle for the empty-context case (the sigVer corpus has no such entries).

use backbone_pqcrypto_internals::kat::FixedRng;
use backbone_sphincs::sha2_128f;
use backbone_sphincs::sha2_128s;
use backbone_sphincs::sha2_192f;
use backbone_sphincs::sha2_192s;
use backbone_sphincs::sha2_256f;
use backbone_sphincs::sha2_256s;
use backbone_sphincs::shake128f;
use backbone_sphincs::shake128s;
use backbone_sphincs::shake192f;
use backbone_sphincs::shake192s;
use backbone_sphincs::shake256f;
use backbone_sphincs::shake256s;
use backbone_sphincs::HashAlgorithm;

// 1. Pure-mode roundtrips.

macro_rules! roundtrip_test {
    ($name:ident, $module:ident) => {
        #[test]
        fn $name() {
            let msg = b"Hello, SPHINCS+!";
            let (pk, sk) = $module::keygen().unwrap();
            let sig = $module::sign(&sk, msg, None, None).unwrap();
            assert!(
                $module::verify(&pk, msg, &sig, None, None).is_ok(),
                "Roundtrip verification failed for {}",
                stringify!($module)
            );
        }
    };
}

roundtrip_test!(roundtrip_shake_128s, shake128s);
roundtrip_test!(roundtrip_shake_128f, shake128f);
roundtrip_test!(roundtrip_shake_192s, shake192s);
roundtrip_test!(roundtrip_shake_192f, shake192f);
roundtrip_test!(roundtrip_shake_256s, shake256s);
roundtrip_test!(roundtrip_shake_256f, shake256f);

roundtrip_test!(roundtrip_sha2_128s, sha2_128s);
roundtrip_test!(roundtrip_sha2_128f, sha2_128f);
roundtrip_test!(roundtrip_sha2_192s, sha2_192s);
roundtrip_test!(roundtrip_sha2_192f, sha2_192f);
roundtrip_test!(roundtrip_sha2_256s, sha2_256s);
roundtrip_test!(roundtrip_sha2_256f, sha2_256f);

// 2. Hash-SLH-DSA (pre-hash) roundtrips.

#[test]
fn shake128f_prehash_roundtrip() {
    let (pk, sk) = shake128f::keygen_with_rng(&mut FixedRng::new(vec![0x42u8; 48])).unwrap();
    let hash = &[0xabu8; 32];
    let optrand = &[7u8; 16];
    for hash_algorithm in [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Shake256,
    ] {
        let sig = shake128f::sign_with_rng(
            &sk,
            hash,
            &mut FixedRng::new(optrand.to_vec()),
            Some(b"ctx"),
            Some(hash_algorithm),
        )
        .unwrap();
        assert!(
            shake128f::verify(&pk, hash, &sig, Some(b"ctx"), Some(hash_algorithm)).is_ok(),
            "{:?}",
            hash_algorithm
        );
    }
}

#[test]
fn sha2_256f_prehash_roundtrip() {
    let (pk, sk) = sha2_256f::keygen_with_rng(&mut FixedRng::new(vec![0x42u8; 96])).unwrap();
    let hash = &[0xabu8; 32];
    let optrand = &[7u8; 32];
    for hash_algorithm in [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Shake256,
    ] {
        let sig = sha2_256f::sign_with_rng(
            &sk,
            hash,
            &mut FixedRng::new(optrand.to_vec()),
            Some(b"ctx"),
            Some(hash_algorithm),
        )
        .unwrap();
        assert!(
            sha2_256f::verify(&pk, hash, &sig, Some(b"ctx"), Some(hash_algorithm)).is_ok(),
            "{:?}",
            hash_algorithm
        );
    }
}

// 3. Pure mode ≡ context path with empty context (C1 regression).

macro_rules! pure_equals_empty_ctx {
    ($name:ident, $mod:ident) => {
        #[test]
        fn $name() {
            let seed = [0x42u8; 48];
            let (pk, sk) =
                backbone_sphincs::$mod::keygen_with_rng(&mut FixedRng::new(seed.to_vec()))
                    .expect("keygen");
            let msg = b"message to be signed";
            let optrand = [7u8; 48];
            let sig_pure = backbone_sphincs::$mod::sign_with_rng(
                &sk,
                msg,
                &mut FixedRng::new(optrand.to_vec()),
                None,
                None,
            )
            .expect("pure sign");
            let sig_ctx = backbone_sphincs::$mod::sign_with_rng(
                &sk,
                msg,
                &mut FixedRng::new(optrand.to_vec()),
                Some(&[]),
                None,
            )
            .expect("ctx sign");
            assert_eq!(
                sig_pure.sig, sig_ctx.sig,
                "pure mode must equal context mode with empty context"
            );
            assert!(backbone_sphincs::$mod::verify(&pk, msg, &sig_pure, None, None).is_ok());
            assert!(backbone_sphincs::$mod::verify(&pk, msg, &sig_ctx, Some(&[]), None).is_ok());
        }
    };
}

pure_equals_empty_ctx!(pure_equals_empty_ctx_sha2_128s, sha2_128s);
pure_equals_empty_ctx!(pure_equals_empty_ctx_sha2_128f, sha2_128f);
pure_equals_empty_ctx!(pure_equals_empty_ctx_sha2_192s, sha2_192s);
pure_equals_empty_ctx!(pure_equals_empty_ctx_sha2_192f, sha2_192f);
pure_equals_empty_ctx!(pure_equals_empty_ctx_sha2_256s, sha2_256s);
pure_equals_empty_ctx!(pure_equals_empty_ctx_sha2_256f, sha2_256f);
pure_equals_empty_ctx!(pure_equals_empty_ctx_shake128s, shake128s);
pure_equals_empty_ctx!(pure_equals_empty_ctx_shake128f, shake128f);
pure_equals_empty_ctx!(pure_equals_empty_ctx_shake192s, shake192s);
pure_equals_empty_ctx!(pure_equals_empty_ctx_shake192f, shake192f);
pure_equals_empty_ctx!(pure_equals_empty_ctx_shake256s, shake256s);
pure_equals_empty_ctx!(pure_equals_empty_ctx_shake256f, shake256f);
