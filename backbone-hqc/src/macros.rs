/// Macro to generate the public API for an HQC variant module.
///
/// Generates `PublicKey`, `SecretKey`, `Encapsulation` types, along with
/// `keygen`, `keypair_from_seed`, `encaps`, `encaps_deterministic`, `decaps`,
/// `AsRef` impls, and inline tests.
///
/// `$params`: The Params implementor (e.g. `Hqc128`).
/// `$ss_size`: Shared secret size in bytes (32 for HQC).
/// `$doc_variant`: Display name for doc comments (e.g. `"HQC-1"`).
/// `$doc_sec`: Security category (e.g. `"1"`).
#[macro_export]
macro_rules! define_variant {
    ($params:ident, $ss_size:expr, $doc_variant:expr, $doc_sec:expr) => {
        use $crate::error::Error;
        use $crate::params::$params;
        use alloc::vec::Vec;
        #[cfg(feature = "zeroize")]
        use zeroize::Zeroize;

        const _CT_BYTES: usize = <$params as $crate::params::Params>::CT_BYTES;


        #[doc = concat!($doc_variant, " public key.")]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct PublicKey {
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
        #[cfg_attr(feature = "zeroize", derive(Zeroize))]
        #[cfg_attr(feature = "zeroize", zeroize(drop))]
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
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct Encapsulation {
            /// The shared secret.
            pub shared_secret: [u8; $ss_size],
            pub ciphertext: Vec<u8>,
        }


        #[doc = concat!("Generate a ", $doc_variant, " keypair deterministically from a seed.")]
        pub fn keygen(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error> {
            if seed.len() != 32 && seed.len() != 48 {
                return Err(Error::InvalidSeedLength);
            }
            let (pk, sk) = $crate::kem::keygen_from_seed::<$params>(seed)?;
            Ok((PublicKey { pk }, SecretKey { sk }))
        }

        pub fn keypair_from_seed(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error> {
            keygen(seed)
        }


        #[doc = concat!("Encapsulate a shared secret under a ", $doc_variant, " public key.")]
        ///
        /// Uses system randomness. Returns an [`Encapsulation`] on success.
        pub fn encaps(pk: &PublicKey) -> Result<Encapsulation, Error> {
            let mut ct = [0u8; _CT_BYTES];
            let mut ss = [0u8; $ss_size];
            $crate::kem::encaps::<$params>(&mut ct, &mut ss, &pk.pk)?;
            Ok(Encapsulation {
                shared_secret: ss,
                ciphertext: ct.to_vec(),
            })
        }

        #[doc = concat!("Encapsulate a shared secret under a ", $doc_variant, " public key using a specific seed.")]
        ///
        /// The seed is expanded via SHAKE-256 to derive the encapsulation randomness.
        /// Returns an [`Encapsulation`] on success.
        pub fn encaps_deterministic(
            pk: &PublicKey,
            seed: &[u8],
        ) -> Result<Encapsulation, Error> {
            let mut ct = [0u8; _CT_BYTES];
            let mut ss = [0u8; $ss_size];
            $crate::kem::encaps_from_seed::<$params>(&mut ct, &mut ss, &pk.pk, seed)?;
            Ok(Encapsulation {
                shared_secret: ss,
                ciphertext: ct.to_vec(),
            })
        }

        #[doc = concat!("Decapsulate a shared secret from a ciphertext using a ", $doc_variant, " secret key.")]
        /// Returns the shared secret on success.
        pub fn decaps(sk: &SecretKey, ct: &[u8]) -> Result<[u8; $ss_size], Error> {
            let mut ss = [0u8; $ss_size];
            $crate::kem::decaps::<$params>(&mut ss, ct, sk.as_ref())?;
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

            pub fn as_bytes(&self) -> &[u8] {
                &self.sk
            }
        }


        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn test_keygen_deterministic() {
                let seed = b"0123456789abcdef0123456789abcdef";
                let (pk1, sk1) = keygen(seed).unwrap();
                let (pk2, sk2) = keygen(seed).unwrap();
                assert_eq!(pk1.pk, pk2.pk);
                assert_eq!(sk1.as_ref(), sk2.as_ref());
            }

            #[test]
            fn test_keygen_different_seeds() {
                let (pk1, _) = keygen(b"00000000000000000000000000000001").unwrap();
                let (pk2, _) = keygen(b"00000000000000000000000000000002").unwrap();
                assert_ne!(pk1.pk, pk2.pk);
            }

            #[test]
            fn test_keygen_roundtrip() {
                let seed = b"00000000000000000000000000000003";
                let (pk, sk) = keygen(seed).unwrap();
                assert!(!pk.pk.is_empty());
                assert!(!sk.as_ref().is_empty());
                assert_eq!(pk.pk.len(), <$params as $crate::params::Params>::PK_BYTES);
                assert_eq!(sk.as_ref().len(), <$params as $crate::params::Params>::SK_BYTES);
            }

            #[test]
            fn test_encaps_decaps_roundtrip() {
                let seed = b"00000000000000000000000000000004";
                let (pk, sk) = keygen(seed).unwrap();
                let enc = encaps(&pk).unwrap();
                assert_eq!(enc.ciphertext.len(), <$params as $crate::params::Params>::CT_BYTES);
                let ss2 = decaps(&sk, &enc.ciphertext).unwrap();
                assert_eq!(enc.shared_secret, ss2);
            }

            #[test]
            fn test_negative_wrong_key() {
                let seed_a = b"00000000000000000000000000000005";
                let seed_b = b"00000000000000000000000000000006";
                let (pk_a, _) = keygen(seed_a).unwrap();
                let (_, sk_b) = keygen(seed_b).unwrap();
                let enc = encaps(&pk_a).unwrap();
                let result = decaps(&sk_b, &enc.ciphertext);
                assert!(result.is_ok());
                assert_ne!(enc.shared_secret, result.unwrap());
            }

            #[test]
            fn test_negative_corrupted_ct() {
                let seed = b"00000000000000000000000000000007";
                let (pk, sk) = keygen(seed).unwrap();
                let enc = encaps(&pk).unwrap();
                let mut ct = enc.ciphertext.clone();
                ct[10] ^= 0x01;
                let result = decaps(&sk, &ct);
                assert!(result.is_ok());
                assert_ne!(enc.shared_secret, result.unwrap());
            }
        }
    };
}
