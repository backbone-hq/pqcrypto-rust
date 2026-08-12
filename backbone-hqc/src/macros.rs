/// Macro to generate the public API for an HQC variant module.
///
/// Generates `PublicKey`, `SecretKey`, `Encapsulation` types, along with
/// `keygen`, `keygen_with_rng`, `encaps`, `encaps_with_rng`, `decaps`,
/// `AsRef` impls, and inline tests.
///
/// `$params`: The Params implementor (e.g. `Hqc128`).
/// `$ss_size`: Shared secret size in bytes (32 for HQC).
/// `$doc_variant`: Display name for doc comments (e.g. `"HQC-1"`).
#[macro_export]
macro_rules! define_variant {
    ($params:ident, $ss_size:expr, $doc_variant:expr) => {
        use $crate::error::Error;
        use $crate::params::$params;
        use alloc::vec;
        use alloc::vec::Vec;
        use $crate::rand_core::CryptoRngCore;
                use zeroize::Zeroize;

        const _CT_BYTES: usize = <$params as $crate::params::Params>::CT_BYTES;

        #[doc = concat!($doc_variant, " public key.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct PublicKey {
            #[doc = concat!("Raw ", $doc_variant, " public key bytes.")]
            pub pk: Vec<u8>,
        }

        impl PublicKey {
            #[doc = concat!("Construct a ", $doc_variant, " public key from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <$params as $crate::params::Params>::PK_BYTES {
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

        /// Key-generation seed length in bytes — the single source of truth for
        /// both `keygen()` (system randomness) and `keygen_with_rng()` (caller RNG).
        const KEYGEN_SEED_LEN: usize = 48;

        #[doc = concat!("Generate a ", $doc_variant, " keypair using system randomness.")]
        pub fn keygen() -> Result<(PublicKey, SecretKey), Error> {
            let mut seed = [0u8; KEYGEN_SEED_LEN];
            getrandom::getrandom(&mut seed).map_err(|_| Error::RngFailure)?;
            keygen_from_seed(&seed)
        }

        #[doc = concat!("Generate a ", $doc_variant, " keypair using a caller-provided RNG.")]
        #[doc = "Draws exactly `KEYGEN_SEED_LEN` bytes from `rng`."]
        pub fn keygen_with_rng(
            rng: &mut impl CryptoRngCore,
        ) -> Result<(PublicKey, SecretKey), Error> {
            let mut seed = [0u8; KEYGEN_SEED_LEN];
            rng.try_fill_bytes(&mut seed).map_err(|_| Error::RngFailure)?;
            keygen_from_seed(&seed)
        }

        fn keygen_from_seed(seed: &[u8; KEYGEN_SEED_LEN]) -> Result<(PublicKey, SecretKey), Error> {
            let (pk, sk) = $crate::kem::keygen_from_seed::<$params>(seed)?;
            Ok((PublicKey { pk }, SecretKey { sk }))
        }

        #[doc = concat!("Encapsulate a shared secret under a ", $doc_variant, " public key.")]
        ///
        /// Uses system randomness. Returns an [`Encapsulation`] on success.
        pub fn encaps(pk: &PublicKey) -> Result<Encapsulation, Error> {
            let mut seed = [0u8; 48];
            getrandom::getrandom(&mut seed).map_err(|_| Error::RngFailure)?;
            encaps_from_seed(pk, &seed)
        }

        #[doc = concat!("Encapsulate a shared secret under a ", $doc_variant, " public key ")]
        #[doc = "using a caller-provided RNG."]
        ///
        /// Draws exactly 48 bytes from `rng`, expanded via SHAKE-256 to derive
        /// the encapsulation randomness. Returns an [`Encapsulation`] on success.
        pub fn encaps_with_rng(
            pk: &PublicKey,
            rng: &mut impl CryptoRngCore,
        ) -> Result<Encapsulation, Error> {
            let mut seed = [0u8; 48];
            rng.try_fill_bytes(&mut seed).map_err(|_| Error::RngFailure)?;
            encaps_from_seed(pk, &seed)
        }

        fn encaps_from_seed(pk: &PublicKey, seed: &[u8; 48]) -> Result<Encapsulation, Error> {
            let mut ct = vec![0u8; _CT_BYTES];
            let mut ss = [0u8; $ss_size];
            $crate::kem::encaps_from_seed::<$params>(&mut ct, &mut ss, pk.as_ref(), seed)?;
            Ok(Encapsulation {
                shared_secret: ss,
                ciphertext: ct,
            })
        }

        #[doc = concat!("Decapsulate a shared secret from a ciphertext using a ", $doc_variant, " secret key.")]
        /// Returns the shared secret on success.
        pub fn decaps(sk: &SecretKey, ciphertext: &[u8]) -> Result<[u8; $ss_size], Error> {
            let mut ss = [0u8; $ss_size];
            $crate::kem::decaps::<$params>(&mut ss, ciphertext, sk.as_ref())?;
            Ok(ss)
        }

        impl AsRef<[u8]> for PublicKey {
            fn as_ref(&self) -> &[u8] {
                &self.pk
            }
        }

        impl AsRef<[u8]> for SecretKey {
            fn as_ref(&self) -> &[u8] {
                &self.sk
            }
        }

        impl SecretKey {
            /// Construct from raw bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <$params as $crate::params::Params>::SK_BYTES {
                    return Err(Error::InvalidSecretKeyLength);
                }
                Ok(Self { sk: bytes.to_vec() })
            }

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
                    b"000000000000000000000000000000000000000000000001".to_vec(),
                ))
                .unwrap();
                let (pk2, _) = keygen_with_rng(&mut FixedRng::new(
                    b"000000000000000000000000000000000000000000000002".to_vec(),
                ))
                .unwrap();
                assert_ne!(pk1.pk, pk2.pk);
            }

            #[test]
            fn test_keygen_roundtrip() {
                let seed = b"000000000000000000000000000000000000000000000003";
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                assert!(!pk.pk.is_empty());
                assert!(!sk.as_ref().is_empty());
                assert_eq!(pk.pk.len(), <$params as $crate::params::Params>::PK_BYTES);
                assert_eq!(sk.as_ref().len(), <$params as $crate::params::Params>::SK_BYTES);
            }

            #[test]
            fn test_encaps_decaps_roundtrip() {
                let seed = b"000000000000000000000000000000000000000000000004";
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                let enc = encaps(&pk).unwrap();
                assert_eq!(enc.ciphertext.len(), <$params as $crate::params::Params>::CT_BYTES);
                let ss2 = decaps(&sk, &enc.ciphertext).unwrap();
                assert_eq!(enc.shared_secret, ss2);
            }

            #[test]
            fn test_negative_wrong_key() {
                let seed_a = b"000000000000000000000000000000000000000000000005";
                let seed_b = b"000000000000000000000000000000000000000000000006";
                let (pk_a, _) = keygen_with_rng(&mut FixedRng::new(seed_a.to_vec())).unwrap();
                let (_, sk_b) = keygen_with_rng(&mut FixedRng::new(seed_b.to_vec())).unwrap();
                let enc = encaps(&pk_a).unwrap();
                let result = decaps(&sk_b, &enc.ciphertext);
                assert!(result.is_ok());
                assert_ne!(enc.shared_secret, result.unwrap());
            }

            #[test]
            fn test_negative_corrupted_ct() {
                let seed = b"000000000000000000000000000000000000000000000007";
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                let enc = encaps(&pk).unwrap();
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
                let seed = b"000000000000000000000000000000000000000000000008";
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                let enc = encaps(&pk).unwrap();
                assert!(
                    decaps(&sk, &[]).is_err(),
                    "decaps with empty ct should fail"
                );
                assert!(
                    decaps(&sk, &enc.ciphertext[..enc.ciphertext.len() / 2]).is_err(),
                    "decaps with truncated ct should fail"
                );
            }

            #[test]
            fn test_negative_invalid_sk_len() {
                assert!(
                    SecretKey::from_bytes(&[]).is_err(),
                    "from_bytes with empty data should fail"
                );
                assert!(
                    SecretKey::from_bytes(&[0u8; 1]).is_err(),
                    "from_bytes with too-short data should fail"
                );
            }
        }
    };
}
