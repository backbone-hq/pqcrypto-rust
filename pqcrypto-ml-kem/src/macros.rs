/// Define a variant module for ML-KEM (FIPS 203) parameter sets.
///
/// Generates `PublicKey`, `SecretKey`, and `Encapsulation` structs along with
/// `keygen`, `keypair_from_seed`, `encaps`, `encaps_deterministic`, and `decaps`
/// functions that delegate to the const-generic `kem` module using the given
/// parameter struct.
#[macro_export]
macro_rules! define_variant {
    ($params:ident, $ss_size:expr, $doc_variant:expr, $doc_sec:expr) => {
        use $crate::params::$params;
        use alloc::vec::Vec;
        #[cfg(feature = "zeroize")]
        use zeroize::Zeroize;

        const _K: usize = <$params as $crate::params::Params>::K;
        const _ETA1: usize = <$params as $crate::params::Params>::ETA1;
        const _ETA2: usize = <$params as $crate::params::Params>::ETA2;
        const _DU: usize = <$params as $crate::params::Params>::DU;
        const _DV: usize = <$params as $crate::params::Params>::DV;
        const _PK_SIZE: usize = <$params as $crate::params::Params>::PK_SIZE;
        const _CT_SIZE: usize = <$params as $crate::params::Params>::CT_SIZE;

        // PublicKey struct
        #[doc = concat!($doc_variant, " public key.")]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct PublicKey {
            /// The raw public key bytes.
            pub pk: Vec<u8>,
        }

        impl PublicKey {
            #[doc = concat!("Construct an ", $doc_variant, " public key from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, $crate::error::Error> {
                if bytes.len() != _PK_SIZE {
                    return Err($crate::error::Error::InvalidKeyLength);
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

        impl SecretKey {
            /// Construct from raw bytes (validates length).
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, $crate::error::Error> {
                if bytes.len() != _PK_SIZE + _K * 384 + 64 {
                    return Err($crate::error::Error::InvalidSecretKeyLength);
                }
                Ok(Self { sk: bytes.to_vec() })
            }

            /// Return the raw secret key bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.sk
            }
        }

        // Encapsulation struct
        /// Result of a successful encapsulation.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct Encapsulation {
            /// The shared secret (32 bytes).
            pub shared_secret: [u8; $ss_size],
            /// The ciphertext.
            pub ciphertext: Vec<u8>,
        }

        #[doc = concat!("Generate an ", $doc_variant, " keypair deterministically from a seed.")]
        pub fn keygen(seed: &[u8]) -> Result<(PublicKey, SecretKey), $crate::error::Error> {
            if seed.len() != 32 {
                return Err($crate::error::Error::InvalidKeyLength);
            }
            let (pk, sk) = $crate::kem::keygen_from_seed::<_K>(seed, _ETA1, _ETA2);
            Ok((PublicKey { pk }, SecretKey { sk }))
        }

        /// Generate a keypair from a seed (alias for keygen).
        pub fn keypair_from_seed(seed: &[u8]) -> Result<(PublicKey, SecretKey), $crate::error::Error> {
            keygen(seed)
        }

        #[doc = concat!("Encapsulate a shared secret under an ", $doc_variant, " public key.")]
        pub fn encaps(pk: &PublicKey) -> Result<Encapsulation, $crate::error::Error> {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|_| $crate::error::Error::RngFailure)?;
            encaps_deterministic(pk, &seed)
        }

        #[doc = concat!("Encapsulate a shared secret under an ", $doc_variant, " public key using a specific seed.")]
        pub fn encaps_deterministic(
            pk: &PublicKey,
            seed: &[u8],
        ) -> Result<Encapsulation, $crate::error::Error> {
            if pk.pk.len() != _PK_SIZE {
                return Err($crate::error::Error::InvalidKeyLength);
            }
            if seed.len() != 32 {
                return Err($crate::error::Error::InvalidKeyLength);
            }
            if !$crate::kem::check_public_key::<_K>(&pk.pk) {
                return Err($crate::error::Error::InvalidPublicKey);
            }
            let m: &[u8; 32] = seed.try_into().expect("length checked above");
            let enc = $crate::kem::encaps_internal::<_K>(&pk.pk, m, _ETA1, _ETA2, _DU, _DV)?;
            Ok(Encapsulation { shared_secret: enc.shared_secret, ciphertext: enc.ciphertext })
        }

        #[doc = concat!("Decapsulate a shared secret from a ciphertext using an ", $doc_variant, " secret key.")]
        pub fn decaps(sk: &SecretKey, ct: &[u8]) -> Result<[u8; 32], $crate::error::Error> {
            if sk.as_ref().len() != _PK_SIZE + _K * 384 + 64 {
                return Err($crate::error::Error::InvalidSecretKeyLength);
            }
            if ct.len() != _CT_SIZE {
                return Err($crate::error::Error::InvalidCiphertextLength);
            }
            $crate::kem::decaps_internal::<_K>(
                sk.as_ref(), ct, _ETA1, _ETA2, _DU, _DV, _PK_SIZE,
            )
        }

        // AsRef impls
        impl AsRef<[u8]> for PublicKey {
            fn as_ref(&self) -> &[u8] { &self.pk }
        }
        impl AsRef<[u8]> for SecretKey {
            fn as_ref(&self) -> &[u8] { &self.sk }
        }
    };
}
