//! Transcript consistency tests for Classic McEliece.

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
    ($test_name:ident, $variant:ident, $expected_hash:literal) => {
        #[test]
        fn $test_name() {
            use pqcrypto_mceliece::$variant::*;

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
                let enc = encaps_deterministic(&pk, &seed).expect("encaps");
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
    mceliece348864_transcript,
    mceliece348864,
    "648a687e3fdeff3410a83abc66956752dea933fb951637084ad2546361d191f9"
);
transcript_kat!(
    mceliece348864f_transcript,
    mceliece348864f,
    "648a687e3fdeff3410a83abc66956752dea933fb951637084ad2546361d191f9"
);
transcript_kat!(
    mceliece460896_transcript,
    mceliece460896,
    "b3fa7295e112d064154612649e8caac4a6db07086ad3df82ee7fc5117638706a"
);
transcript_kat!(
    mceliece460896f_transcript,
    mceliece460896f,
    "b3fa7295e112d064154612649e8caac4a6db07086ad3df82ee7fc5117638706a"
);
transcript_kat!(
    mceliece6688128_transcript,
    mceliece6688128,
    "361f4190ac92ea2654c6f69c2508409932cc54c9b5e69427b2497d6cab8a6152"
);
transcript_kat!(
    mceliece6688128f_transcript,
    mceliece6688128f,
    "361f4190ac92ea2654c6f69c2508409932cc54c9b5e69427b2497d6cab8a6152"
);
transcript_kat!(
    mceliece6960119_transcript,
    mceliece6960119,
    "ca2d92fbf6933422693afb81a61562f48cf8d27db081d9aef17b2b38a20793a8"
);
transcript_kat!(
    mceliece6960119f_transcript,
    mceliece6960119f,
    "ca2d92fbf6933422693afb81a61562f48cf8d27db081d9aef17b2b38a20793a8"
);
transcript_kat!(
    mceliece8192128_transcript,
    mceliece8192128,
    "0b18770433150f128dc098005945b9684cf98978ad3fd2439f474ff0c7038724"
);
transcript_kat!(
    mceliece8192128f_transcript,
    mceliece8192128f,
    "0b18770433150f128dc098005945b9684cf98978ad3fd2439f474ff0c7038724"
);
