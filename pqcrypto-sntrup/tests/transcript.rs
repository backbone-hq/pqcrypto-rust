//! Transcript consistency tests for Streamlined NTRU Prime.

use sha2::{Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

fn shake256<const OUT: usize>(input: &[u8]) -> [u8; OUT] {
    let mut shake = Shake256::default();
    Update::update(&mut shake, input);
    let mut reader = shake.finalize_xof();
    let mut out = [0u8; OUT];
    reader.read(&mut out);
    out
}

fn update_hex_line(hasher: &mut Sha256, label: &[u8], data: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    Digest::update(hasher, label);
    Digest::update(hasher, b" = ");
    for &byte in data {
        Digest::update(
            hasher,
            [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]],
        );
    }
    Digest::update(hasher, b"\n");
}

macro_rules! transcript_kat {
    ($test_name:ident, $variant:ident, $p:ty, $expected_hash:literal) => {
        #[test]
        fn $test_name() {
            use pqcrypto_sntrup::params::Params;
            use pqcrypto_sntrup::$variant::*;

            const NUM_TESTS: usize = 100;
            let seed_init = [
                32u8, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
            ];
            let mut coins = shake256::<96>(&seed_init);
            let mut transcript = Sha256::new();

            for _ in 0..NUM_TESTS {
                coins = shake256::<96>(&coins);
                let seed: [u8; 32] = coins[..32].try_into().unwrap();

                let (pk, sk) = keygen(&seed).expect("keygen");
                assert_eq!(pk.pk.len(), <$p as Params>::PK_BYTES);
                assert_eq!(sk.as_ref().len(), <$p as Params>::SK_BYTES);

                let enc = encaps_deterministic(&pk, &seed).expect("encaps");
                assert_eq!(enc.ciphertext.len(), <$p as Params>::CT_BYTES);

                let dec_ss = decaps(&sk, &enc.ciphertext).expect("decaps");
                assert_eq!(dec_ss.as_slice(), enc.shared_secret.as_slice());

                update_hex_line(&mut transcript, b"pk", &pk.pk);
                update_hex_line(&mut transcript, b"sk", sk.as_ref());
                update_hex_line(&mut transcript, b"ct", &enc.ciphertext);
                update_hex_line(&mut transcript, b"ss", &enc.shared_secret);
            }

            let got = format!("{:x}", transcript.finalize());
            assert_eq!(
                got,
                $expected_hash,
                "transcript hash mismatch for {}",
                stringify!($variant)
            );
        }
    };
}

transcript_kat!(
    sntrup653_transcript,
    sntrup653,
    pqcrypto_sntrup::params::Sntrup653,
    "ecc63cc0071642f67d5147b14a720054e8b73e2a9fc928862bee18743fb016f7"
);
transcript_kat!(
    sntrup761_transcript,
    sntrup761,
    pqcrypto_sntrup::params::Sntrup761,
    "8a1507bab3d5ee424ad2e82b9362e25b381ddc5f1bce76d1650381d3150d37c8"
);
transcript_kat!(
    sntrup857_transcript,
    sntrup857,
    pqcrypto_sntrup::params::Sntrup857,
    "1f9e8b3af69a0757a780bbcc1e1c548e6f0beddc1338a0604aa1aca838658b28"
);
