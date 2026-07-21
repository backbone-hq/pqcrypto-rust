//! Roundtrip tests for all SPHINCS+ variants.
use pqcrypto_sphincs::params::Params;
use pqcrypto_sphincs::params::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s,
};
use pqcrypto_sphincs::sha2_128f;
use pqcrypto_sphincs::sha2_128s;
use pqcrypto_sphincs::sha2_192f;
use pqcrypto_sphincs::sha2_192s;
use pqcrypto_sphincs::sha2_256f;
use pqcrypto_sphincs::sha2_256s;
use pqcrypto_sphincs::shake128f;
use pqcrypto_sphincs::shake128s;
use pqcrypto_sphincs::shake192f;
use pqcrypto_sphincs::shake192s;
use pqcrypto_sphincs::shake256f;
use pqcrypto_sphincs::shake256s;

macro_rules! roundtrip_test {
    ($name:ident, $module:ident, $variant:ty) => {
        #[test]
        fn $name() {
            let seed = vec![0x42u8; <$variant>::SEED_BYTES];
            let msg = b"Hello, SPHINCS+!";
            let (pk, sk) = $module::keygen(&seed).unwrap();
            let sig = $module::sign(&sk, msg).unwrap();
            assert!(
                $module::verify(&pk, msg, &sig),
                "Roundtrip verification failed for {}",
                stringify!($variant)
            );
        }
    };
}

// SHAKE variants
roundtrip_test!(roundtrip_shake_128s, shake128s, Shake128s);
roundtrip_test!(roundtrip_shake_128f, shake128f, Shake128f);
roundtrip_test!(roundtrip_shake_192s, shake192s, Shake192s);
roundtrip_test!(roundtrip_shake_192f, shake192f, Shake192f);
roundtrip_test!(roundtrip_shake_256s, shake256s, Shake256s);
roundtrip_test!(roundtrip_shake_256f, shake256f, Shake256f);

// SHA-2 variants
roundtrip_test!(roundtrip_sha2_128s, sha2_128s, Sha2_128s);
roundtrip_test!(roundtrip_sha2_128f, sha2_128f, Sha2_128f);
roundtrip_test!(roundtrip_sha2_192s, sha2_192s, Sha2_192s);
roundtrip_test!(roundtrip_sha2_192f, sha2_192f, Sha2_192f);
roundtrip_test!(roundtrip_sha2_256s, sha2_256s, Sha2_256s);
roundtrip_test!(roundtrip_sha2_256f, sha2_256f, Sha2_256f);
