/// Helper macro to define a NTRUPLR variant (e.g. ntruplr653, ntruplr761).
///
/// Generates `PublicKey`, `SecretKey`, `Encapsulation` structs,
/// plus `keygen`, `keypair_from_seed`, `encaps`, `encaps_deterministic`,
/// and `decaps` functions using a `Params` implementor.
#[macro_export]
macro_rules! define_variant {
    ($params:ident, $ss_size:expr, $doc_variant:expr, $doc_sec:expr) => {
        use $crate::error::Error;
        use $crate::params::$params;
        use alloc::vec::Vec;
        #[cfg(feature = "zeroize")]
        use zeroize::Zeroize;

        // Derive local consts from Params trait
        const _P: usize = <$params as $crate::params::Params>::P;
        const _Q: i16 = <$params as $crate::params::Params>::Q;
        const _W: usize = <$params as $crate::params::Params>::W;
        const _PK_BYTES: usize = <$params as $crate::params::Params>::PK_BYTES;
        const _SK_BYTES: usize = <$params as $crate::params::Params>::SK_BYTES;
        const _CT_BYTES: usize = <$params as $crate::params::Params>::CT_BYTES;
        const _TAU0: i32 = <$params as $crate::params::Params>::TAU0;
        const _TAU1: i32 = <$params as $crate::params::Params>::TAU1;
        const _TAU2: i32 = <$params as $crate::params::Params>::TAU2;
        const _TAU3: i32 = <$params as $crate::params::Params>::TAU3;

        // PublicKey struct
        #[doc = concat!($doc_variant, " public key.")]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct PublicKey {
            /// The raw public key bytes.
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

        // SecretKey struct
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
            /// The shared secret (32 bytes).
            pub shared_secret: [u8; $ss_size],
            /// The ciphertext.
            pub ciphertext: Vec<u8>,
        }

        #[doc = concat!("Generate an ", $doc_variant, " keypair deterministically from a seed.")]
        pub fn keygen(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error> {
            let mut pk = alloc::vec![0u8; _PK_BYTES];
            let mut sk = alloc::vec![0u8; _SK_BYTES];
            $crate::kem::keypair::<_P, _Q, _TAU0, _TAU1, _TAU2, _TAU3>(&mut pk, &mut sk, seed, _W)?;
            Ok((PublicKey { pk }, SecretKey { sk }))
        }

        #[doc = concat!("Generate a keypair from a seed (alias for [`keygen`]).")]
        pub fn keypair_from_seed(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error> {
            keygen(seed)
        }

        #[doc = concat!("Encapsulate a shared secret under an ", $doc_variant, " public key.")]
        pub fn encaps(pk: &PublicKey) -> Result<Encapsulation, Error> {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|_| Error::RngFailure)?;
            encaps_deterministic(pk, &seed)
        }

        #[doc = concat!("Encapsulate a shared secret under an ", $doc_variant, " public key using a specific seed.")]
        pub fn encaps_deterministic(
            pk: &PublicKey,
            seed: &[u8],
        ) -> Result<Encapsulation, Error> {
            let (ss, ct_vec) = $crate::kem::encaps::<_P, _Q, _TAU0, _TAU1, _TAU2, _TAU3>(&pk.pk, seed, _W, _CT_BYTES)?;
            Ok(Encapsulation { shared_secret: ss, ciphertext: ct_vec })
        }

        #[doc = concat!("Decapsulate a shared secret from a ciphertext using an ", $doc_variant, " secret key.")]
        pub fn decaps(sk: &SecretKey, ct: &[u8]) -> Result<[u8; $ss_size], Error> {
            $crate::kem::decaps::<_P, _Q, _TAU0, _TAU1, _TAU2, _TAU3>(sk.as_ref(), ct, _W)
        }

        // AsRef impls
        impl AsRef<[u8]> for PublicKey {
            fn as_ref(&self) -> &[u8] { &self.pk }
        }
        impl AsRef<[u8]> for SecretKey {
            fn as_ref(&self) -> &[u8] { &self.sk }
        }

        impl SecretKey {
            /// Construct from raw bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != _SK_BYTES {
                    return Err(Error::InvalidSecretKeyLength);
                }
                Ok(Self { sk: bytes.to_vec() })
            }

            /// Return the raw secret key bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.sk
            }
        }

        // Inline tests
        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn test_keygen_deterministic() {
                let seed = b"0123456789abcdef0123456789abcdef0123456789abcdef012345678";
                let (pk1, sk1) = keygen(seed).unwrap();
                let (pk2, sk2) = keygen(seed).unwrap();
                assert_eq!(pk1.pk, pk2.pk);
                assert_eq!(sk1.as_ref(), sk2.as_ref());
            }

            #[test]
            fn test_keygen_different_seeds() {
                let (pk1, _) = keygen(b"seed123456789012345678901234567890123456789").unwrap();
                let (pk2, _) = keygen(b"SEED123456789012345678901234567890123456789").unwrap();
                assert_ne!(pk1.pk, pk2.pk);
            }

            #[test]
            fn test_encaps_decaps_roundtrip() {
                let seed = b"0123456789abcdef0123456789abcdef";
                let (pk, sk) = keygen(seed).unwrap();
                let enc = encaps(&pk).unwrap();
                let ss_dec = decaps(&sk, &enc.ciphertext).unwrap();
                assert_eq!(enc.shared_secret, ss_dec);
            }

            #[test]
            fn test_negative_wrong_key() {
                let (pk_a, _) = keygen(b"00001111222233334444555566667777").unwrap();
                let (_, sk_b) = keygen(b"77776666555544443333222211110000").unwrap();
                let enc = encaps(&pk_a).unwrap();
                let wrong_ss = decaps(&sk_b, &enc.ciphertext).unwrap();
                assert_ne!(enc.shared_secret, wrong_ss);
            }

            #[test]
            fn test_negative_corrupted_ct() {
                let seed = b"0123456789abcdef0123456789abcdef";
                let (pk, sk) = keygen(seed).unwrap();
                let rng_seed = [0x13u8; 32];
                let mut enc = encaps_deterministic(&pk, &rng_seed).unwrap();
                enc.ciphertext[0] ^= 0x01;
                let tampered_ss = decaps(&sk, &enc.ciphertext).unwrap();
                assert_ne!(enc.shared_secret, tampered_ss);
            }
        }
    };
}
