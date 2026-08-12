/// Define a variant module for ML-KEM (FIPS 203) parameter sets.
///
/// Generates `PublicKey`, `SecretKey`, and `Encapsulation` structs along with
/// `keygen`, `keygen_with_rng`, `encaps`, `encaps_with_rng`, and `decaps`
/// functions that delegate to the const-generic `kem` module using the given
/// parameter struct.
#[macro_export]
macro_rules! define_variant {
    ($params:ident, $ss_size:expr, $doc_variant:expr) => {

        use $crate::error::Error;
        use $crate::params::$params;
        use alloc::vec::Vec;
        use $crate::rand_core::CryptoRngCore;
        use backbone_pqcrypto_internals::secret::SecretArray;
                use zeroize::Zeroize;

        const _K: usize = <$params as $crate::params::Params>::K;
        const _ETA1: usize = <$params as $crate::params::Params>::ETA1;
        const _ETA2: usize = <$params as $crate::params::Params>::ETA2;
        const _DU: usize = <$params as $crate::params::Params>::DU;
        const _DV: usize = <$params as $crate::params::Params>::DV;
        const _PK_BYTES: usize = <$params as $crate::params::Params>::PK_BYTES;
        const _CT_BYTES: usize = <$params as $crate::params::Params>::CT_BYTES;

        #[doc = concat!($doc_variant, " public key.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct PublicKey {
            #[doc = concat!("Raw ", $doc_variant, " public key bytes.")]
            pub pk: Vec<u8>,
        }

        impl PublicKey {
            #[doc = concat!("Construct an ", $doc_variant, " public key from raw bytes.")]
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
            /// Construct from raw bytes (validates length).
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                let expected_len = _PK_BYTES + _K * 384 + 64;
                if bytes.len() != expected_len {
                    return Err(Error::InvalidSecretKeyLength);
                }
                Ok(Self { sk: bytes.to_vec() })
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

        /// Key-generation randomness length in bytes — the single source of truth for
        /// both `keygen()` (system randomness) and `keygen_with_rng()` (caller RNG):
        /// the FIPS 203 `(d, z)` pair.
        const KEYGEN_SEED_LEN: usize = 64;

        #[doc = concat!("Generate an ", $doc_variant, " keypair using system randomness.")]
        pub fn keygen() -> Result<(PublicKey, SecretKey), Error> {
            let mut seed = SecretArray::<u8, KEYGEN_SEED_LEN>::new();
            getrandom::getrandom(seed.as_mut()).map_err(|_| Error::RngFailure)?;
            keygen_with_seed(&seed)
        }

        #[doc = concat!("Generate an ", $doc_variant, " keypair using a caller-provided RNG.")]
        #[doc = "Draws 64 bytes from `rng` — the FIPS 203 `(d, z)` — and expands them "]
        #[doc = "into a keypair."]
        pub fn keygen_with_rng(
            rng: &mut impl CryptoRngCore,
        ) -> Result<(PublicKey, SecretKey), Error> {
            let mut seed = SecretArray::<u8, KEYGEN_SEED_LEN>::new();
            rng.try_fill_bytes(seed.as_mut()).map_err(|_| Error::RngFailure)?;
            keygen_with_seed(&seed)
        }

        fn keygen_with_seed(
            seed: &[u8; KEYGEN_SEED_LEN],
        ) -> Result<(PublicKey, SecretKey), Error> {
            let mut d = SecretArray::<u8, 32>::new();
            let mut z = SecretArray::<u8, 32>::new();
            d.copy_from_slice(&seed[..32]);
            z.copy_from_slice(&seed[32..]);
            let (pk, sk) = $crate::kem::keygen_internal::<_K>(_ETA1, _ETA2, &d, &z);
            Ok((PublicKey { pk }, SecretKey { sk }))
        }

        #[doc = concat!("Encapsulate a shared secret under an ", $doc_variant, " public key.")]
        pub fn encaps(pk: &PublicKey) -> Result<Encapsulation, Error> {
            let mut m = SecretArray::<u8, 32>::new();
            getrandom::getrandom(m.as_mut()).map_err(|_| Error::RngFailure)?;
            encaps_with_m(pk, &m)
        }

        #[doc = concat!("Encapsulate a shared secret under an ", $doc_variant, " public key ")]
        #[doc = "using a caller-provided RNG."]
        #[doc = "Draws the 32-byte message `m` from `rng` (FIPS 203 encaps randomness)."]
        pub fn encaps_with_rng(
            pk: &PublicKey,
            rng: &mut impl CryptoRngCore,
        ) -> Result<Encapsulation, Error> {
            let mut m = SecretArray::<u8, 32>::new();
            rng.try_fill_bytes(m.as_mut()).map_err(|_| Error::RngFailure)?;
            encaps_with_m(pk, &m)
        }

        fn encaps_with_m(pk: &PublicKey, m: &[u8; 32]) -> Result<Encapsulation, Error> {
            if pk.pk.len() != _PK_BYTES {
                return Err(Error::InvalidKeyLength);
            }
            if !$crate::kem::check_public_key::<_K>(&pk.pk) {
                return Err(Error::InvalidPublicKey);
            }
            let enc = $crate::kem::encaps_internal::<_K>(&pk.pk, m, _ETA1, _ETA2, _DU, _DV)?;
            Ok(Encapsulation {
                shared_secret: enc.shared_secret,
                ciphertext: enc.ciphertext,
            })
        }

        #[doc = concat!("Decapsulate a shared secret from a ciphertext using an ", $doc_variant, " secret key.")]
        pub fn decaps(sk: &SecretKey, ciphertext: &[u8]) -> Result<[u8; $ss_size], Error> {
            if sk.as_ref().len() != _PK_BYTES + _K * 384 + 64 {
                return Err(Error::InvalidSecretKeyLength);
            }
            if ciphertext.len() != _CT_BYTES {
                return Err(Error::InvalidCiphertextLength);
            }
            $crate::kem::decaps_internal::<_K>(
                sk.as_ref(), ciphertext, _ETA1, _ETA2, _DU, _DV, _PK_BYTES,
            )
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
            fn test_keygen_roundtrip() {
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(vec![0x01u8; 64])).unwrap();
                assert_eq!(pk.pk.len(), _PK_BYTES);
                assert_eq!(sk.as_ref().len(), _PK_BYTES + _K * 384 + 64);
            }

            #[test]
            fn test_negative_wrong_key() {
                let (pk_a, _) = keygen_with_rng(&mut FixedRng::new(vec![0x01u8; 64])).unwrap();
                let (_, sk_b) = keygen_with_rng(&mut FixedRng::new(vec![0x02u8; 64])).unwrap();
                let msg = [0xabu8; 32];
                let enc = encaps_with_rng(&pk_a, &mut FixedRng::new(msg.to_vec())).unwrap();
                let ss_bad = decaps(&sk_b, &enc.ciphertext).unwrap();
                assert_ne!(enc.shared_secret, ss_bad, "wrong-key decaps must not match");
            }

            #[test]
            fn test_negative_corrupted_ct() {
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(vec![0x01u8; 64])).unwrap();
                let msg = [0xabu8; 32];
                let enc = encaps_with_rng(&pk, &mut FixedRng::new(msg.to_vec())).unwrap();
                let mut ct_vec = enc.ciphertext.to_vec();
                for pos in [
                    0usize,
                    1,
                    ct_vec.len() / 3,
                    ct_vec.len() / 2,
                    ct_vec.len() - 1,
                ] {
                    let orig = ct_vec[pos];
                    ct_vec[pos] ^= 0xff;
                    let ss_bad = decaps(&sk, &ct_vec).unwrap();
                    assert_ne!(
                        enc.shared_secret, ss_bad,
                        "tampered ciphertext byte {pos} produced the real shared secret"
                    );
                    ct_vec[pos] = orig;
                }
            }

            #[test]
            fn test_negative_zero_ct() {
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(vec![0x01u8; 64])).unwrap();
                let msg = [0xabu8; 32];
                let enc = encaps_with_rng(&pk, &mut FixedRng::new(msg.to_vec())).unwrap();
                let zero_ct = vec![0u8; enc.ciphertext.len()];
                let ss_zero = decaps(&sk, &zero_ct).unwrap();
                assert_ne!(
                    enc.shared_secret, ss_zero,
                    "decaps with zero ciphertext should produce a different shared secret"
                );
            }
        }
    };
}
