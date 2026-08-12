/// Helper macro to define a variant (e.g. sntrup653, sntrup761, sntrup857).
///
/// Generates `PublicKey`, `SecretKey`, `Encapsulation` structs,
/// plus `keygen`, `keygen_with_rng`, `encaps`, `encaps_with_rng`,
/// and `decaps` functions using a `Params` implementor.
#[macro_export]
macro_rules! define_variant {
    ($params:ident, $ss_size:expr, $doc_variant:expr) => {
        use $crate::error::Error;
        use $crate::params::$params;
        use alloc::vec::Vec;
        use backbone_pqcrypto_internals::nist_seed_expander::NistSeedExpander;
        use $crate::rand_core::CryptoRngCore;
                use zeroize::Zeroize;

        const _P: usize = <$params as $crate::params::Params>::P;
        const _Q: i16 = <$params as $crate::params::Params>::Q;
        const _W: usize = <$params as $crate::params::Params>::W;
        const _PK_BYTES: usize = <$params as $crate::params::Params>::PK_BYTES;
        const _SK_BYTES: usize = <$params as $crate::params::Params>::SK_BYTES;
        const _CT_BYTES: usize = <$params as $crate::params::Params>::CT_BYTES;

        /// Result of a successful encapsulation.
        #[derive(Clone, PartialEq, Eq, Zeroize)]
        #[zeroize(drop)]
        pub struct Encapsulation {
            #[doc = concat!("Shared secret (", stringify!($ss_size), " bytes).")]
            pub shared_secret: [u8; $ss_size],
            #[doc = concat!("Ciphertext for ", $doc_variant, ".")]
            pub ciphertext: Vec<u8>,
        }

        impl core::fmt::Debug for Encapsulation {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct("Encapsulation")
                    .field("shared_secret", &"[REDACTED]")
                    .field("ciphertext", &self.ciphertext)
                    .finish()
            }
        }

        #[doc = concat!($doc_variant, " public key.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct PublicKey {
            #[doc = concat!("Raw ", $doc_variant, " public key bytes.")]
            pub pk: Vec<u8>,
        }

        impl PublicKey {
            #[doc = concat!("Construct a ", $doc_variant, " public key from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != _PK_BYTES {
                    return Err(Error::InvalidKeyLength);
                }
                Ok(Self { pk: bytes.to_vec() })
            }
        }

        #[doc = concat!($doc_variant, " secret key.")]
        #[derive(Zeroize)]
        #[zeroize(drop)]
        pub struct SecretKey {
            sk: Vec<u8>,
        }

        impl core::fmt::Debug for SecretKey {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct("SecretKey")
                    .field("sk", &"[REDACTED]")
                    .finish()
            }
        }

        impl SecretKey {
            /// Construct from raw bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != _SK_BYTES {
                    return Err(Error::InvalidSecretKeyLength);
                }
                Ok(Self { sk: bytes.to_vec() })
            }

        }

        /// Key-generation seed length in bytes — the single source of truth for
        /// both `keygen()` (system randomness) and `keygen_with_rng()` (caller RNG).
        const KEYGEN_SEED_LEN: usize = 48;

        #[doc = concat!("Generate an ", $doc_variant, " keypair using system randomness.")]
        pub fn keygen() -> Result<(PublicKey, SecretKey), Error> {
            let mut seed = [0u8; KEYGEN_SEED_LEN];
            getrandom::getrandom(&mut seed).map_err(|_| Error::RngFailure)?;
            keygen_with_seed(&seed)
        }

        #[doc = concat!("Generate an ", $doc_variant, " keypair using a caller-provided RNG.")]
        #[doc = "Draws exactly `KEYGEN_SEED_LEN` bytes from `rng`, expanded via the NIST "]
        #[doc = "AES-256-CTR DRBG, matching the official KAT harness."]
        pub fn keygen_with_rng(
            rng: &mut impl CryptoRngCore,
        ) -> Result<(PublicKey, SecretKey), Error> {
            let mut seed = [0u8; KEYGEN_SEED_LEN];
            rng.try_fill_bytes(&mut seed).map_err(|_| Error::RngFailure)?;
            keygen_with_seed(&seed)
        }

        fn keygen_with_seed(
            seed: &[u8; KEYGEN_SEED_LEN],
        ) -> Result<(PublicKey, SecretKey), Error> {
            let mut expander = NistSeedExpander::new(seed);
            let mut pk = alloc::vec![0u8; _PK_BYTES];
            let mut sk = alloc::vec![0u8; _SK_BYTES];
            $crate::kem::keypair_drbg::<_P, _Q>(&mut expander, &mut pk, &mut sk, _W)?;
            Ok((PublicKey { pk }, SecretKey { sk }))
        }

        #[doc = concat!("Encapsulate a shared secret under an ", $doc_variant, " public key.")]
        pub fn encaps(pk: &PublicKey) -> Result<Encapsulation, Error> {
            let mut seed = [0u8; 48];
            getrandom::getrandom(&mut seed).map_err(|_| Error::RngFailure)?;
            encaps_with_seed(pk, &seed)
        }

        #[doc = concat!("Encapsulate a shared secret under an ", $doc_variant, " public key ")]
        #[doc = "using a caller-provided RNG."]
        #[doc = "Draws 48 bytes from `rng`, expanded via SHAKE-256 to derive the encaps "]
        #[doc = "randomness, matching the official harness."]
        pub fn encaps_with_rng(
            pk: &PublicKey,
            rng: &mut impl CryptoRngCore,
        ) -> Result<Encapsulation, Error> {
            let mut seed = [0u8; 48];
            rng.try_fill_bytes(&mut seed).map_err(|_| Error::RngFailure)?;
            encaps_with_seed(pk, &seed)
        }

        fn encaps_with_seed(pk: &PublicKey, seed: &[u8; 48]) -> Result<Encapsulation, Error> {
            let (ss, ct_vec) = $crate::kem::encaps::<_P, _Q>(&pk.pk, seed, _W, _CT_BYTES)?;
            Ok(Encapsulation {
                shared_secret: ss,
                ciphertext: ct_vec,
            })
        }

        #[doc = concat!("Decapsulate a shared secret from a ciphertext using an ", $doc_variant, " secret key.")]
        pub fn decaps(sk: &SecretKey, ciphertext: &[u8]) -> Result<[u8; $ss_size], Error> {
            $crate::kem::decaps::<_P, _Q>(sk.as_ref(), ciphertext, _W)
        }

        impl AsRef<[u8]> for PublicKey {
            fn as_ref(&self) -> &[u8] { &self.pk }
        }
        impl AsRef<[u8]> for SecretKey {
            fn as_ref(&self) -> &[u8] { &self.sk }
        }

        impl TryFrom<&[u8]> for PublicKey {
            type Error = Error;

            fn try_from(bytes: &[u8]) -> Result<Self, Error> {
                Self::from_bytes(bytes)
            }
        }

        impl TryFrom<&[u8]> for SecretKey {
            type Error = Error;

            fn try_from(bytes: &[u8]) -> Result<Self, Error> {
                Self::from_bytes(bytes)
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use alloc::vec;
            use backbone_pqcrypto_internals::kat::FixedRng;

            #[test]
            fn test_keygen_with_rng() {
                let seed = b"0123456789abcdef0123456789abcdef0123456789abcdef";
                let (pk1, sk1) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                let (pk2, sk2) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                assert_eq!(pk1.pk, pk2.pk);
                assert_eq!(sk1.as_ref(), sk2.as_ref());
            }

            #[test]
            fn test_keygen_different_seeds() {
                let (pk1, _) = keygen_with_rng(&mut FixedRng::new(
                    b"seed1234xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_vec(),
                ))
                .unwrap();
                let (pk2, _) = keygen_with_rng(&mut FixedRng::new(
                    b"SEED12340000000000000000000000000000000000000000".to_vec(),
                ))
                .unwrap();
                assert_ne!(pk1.pk, pk2.pk);
            }

            #[test]
            fn test_keygen_roundtrip() {
                let seed = b"test_seed_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                assert!(!pk.pk.is_empty());
                assert!(!sk.as_ref().is_empty());
                assert_eq!(pk.pk.len(), _PK_BYTES);
                assert_eq!(sk.as_ref().len(), _SK_BYTES);
            }

            #[test]
            fn test_encaps_decaps_roundtrip() {
                let seed = b"0123456789abcdef0123456789abcdef0123456789abcdef";
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                let enc = encaps(&pk).unwrap();
                let ss2 = decaps(&sk, &enc.ciphertext).unwrap();
                assert_eq!(enc.shared_secret, ss2);
            }

            #[test]
            fn test_encaps_with_rng() {
                let seed = b"deterministic_keygen_test_1111111111111111111111";
                let r_seed = b"same_r_seed_123456789012345678901234567890123456";
                let (pk, _sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                let enc1 = encaps_with_rng(&pk, &mut FixedRng::new(r_seed.to_vec())).unwrap();
                let enc2 = encaps_with_rng(&pk, &mut FixedRng::new(r_seed.to_vec())).unwrap();
                assert_eq!(enc1.shared_secret, enc2.shared_secret);
                assert_eq!(enc1.ciphertext, enc2.ciphertext);
            }

            #[test]
            fn test_negative_wrong_key() {
                let (pk_a, _) = keygen_with_rng(&mut FixedRng::new(
                    b"000011112222333344445555666677770000000000000000".to_vec(),
                ))
                .unwrap();
                let (_, sk_b) = keygen_with_rng(&mut FixedRng::new(
                    b"aaaaaaaabbbbbbbbccccccccdddddddddddddddddddddddd".to_vec(),
                ))
                .unwrap();
                let enc = encaps(&pk_a).unwrap();
                let result = decaps(&sk_b, &enc.ciphertext).unwrap();
                assert_ne!(enc.shared_secret, result);
            }

            #[test]
            fn test_negative_corrupted_ct() {
                let seed = b"0123456789abcdef0123456789abcdef0123456789abcdef";
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                let enc = encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48])).unwrap();
                for pos in [
                    0usize,
                    1,
                    enc.ciphertext.len() / 3,
                    enc.ciphertext.len() / 2,
                    enc.ciphertext.len() - 1,
                ] {
                    let mut ct = enc.ciphertext.clone();
                    ct[pos] ^= 0xff;
                    let result = decaps(&sk, &ct).expect("same-length tampered ct uses fallback");
                    assert_ne!(
                        enc.shared_secret, result,
                        "tampered ciphertext byte {pos} produced the real shared secret"
                    );
                }
            }

            #[test]
            fn test_negative_invalid_ct_len() {
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(
                    b"0123456789abcdef0123456789abcdef0123456789abcdef".to_vec(),
                ))
                .unwrap();
                let enc = encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48])).unwrap();
                assert_eq!(
                    decaps(&sk, &[]).expect_err("empty ct"),
                    $crate::error::Error::InvalidCiphertextLength
                );
                assert_eq!(
                    decaps(&sk, &enc.ciphertext[..enc.ciphertext.len() - 1])
                        .expect_err("truncated ct"),
                    $crate::error::Error::InvalidCiphertextLength
                );
            }

            #[test]
            fn test_negative_invalid_sk_len() {
                assert!(SecretKey::from_bytes(&[]).is_err());
                assert!(SecretKey::from_bytes(&[0u8; 1]).is_err());
            }
        }
    };
}
