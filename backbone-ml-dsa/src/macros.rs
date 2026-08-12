/// Macro to generate the public API for an ML-DSA variant module.
///
/// Generates `PublicKey`, `SecretKey`, `Signature` types, along with
/// `keygen`, `keygen_with_rng`, `sign`, `sign_with_rng`, `verify`, `AsRef` impls,
/// and inline tests.
///
/// `$params`: The Params implementor (e.g. `Mldsa44`).
/// `$doc_variant`: Display name for doc comments (e.g. `"ML-DSA-44"`).
#[macro_export]
macro_rules! define_variant {
    ($params:ident, $doc_variant:expr) => {
        use alloc::vec;
        use alloc::vec::Vec;
        use backbone_pqcrypto_internals::oid::HashAlgorithm;
        use $crate::error::Error;
        use $crate::params::$params;
        use $crate::params::Params;
        use $crate::rand_core::CryptoRngCore;

        use zeroize::Zeroize;

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

        #[doc = concat!($doc_variant, " public key.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct PublicKey {
            #[doc = concat!("Raw ", $doc_variant, " public key bytes.")]
            pub pk: Vec<u8>,
        }

        #[doc = concat!($doc_variant, " signature.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct Signature {
            #[doc = concat!("Raw ", $doc_variant, " signature bytes.")]
            pub sig: Vec<u8>,
        }

        impl SecretKey {
            #[doc = concat!("Construct an ", $doc_variant, " secret key from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <$params as Params>::SK_BYTES {
                    return Err(Error::InvalidSecretKeyLength);
                }
                Ok(Self { sk: bytes.to_vec() })
            }
        }

        impl PublicKey {
            #[doc = concat!("Construct an ", $doc_variant, " public key from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <$params as Params>::PK_BYTES {
                    return Err(Error::InvalidKeyLength);
                }
                Ok(Self { pk: bytes.to_vec() })
            }
        }

        impl Signature {
            #[doc = concat!("Construct an ", $doc_variant, " signature from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <$params as Params>::SIG_BYTES {
                    return Err(Error::InvalidSignatureLength);
                }
                Ok(Self {
                    sig: bytes.to_vec(),
                })
            }
        }

        /// Key-generation seed length in bytes — the single source of truth for
        /// both `keygen()` (system randomness) and `keygen_with_rng()` (caller RNG).
        const KEYGEN_SEED_LEN: usize = 32;

        #[doc = concat!("Generate an ", $doc_variant, " keypair using system randomness.")]
        pub fn keygen() -> Result<(PublicKey, SecretKey), Error> {
            let mut seed = [0u8; KEYGEN_SEED_LEN];
            getrandom::getrandom(&mut seed).map_err(|_| Error::RngFailure)?;
            keygen_with_seed(&seed)
        }

        #[doc = concat!("Generate an ", $doc_variant, " keypair using a caller-provided RNG.")]
        #[doc = "Draws exactly `KEYGEN_SEED_LEN` bytes from `rng` (the FIPS 204 `xi`)."]
        pub fn keygen_with_rng(
            rng: &mut impl CryptoRngCore,
        ) -> Result<(PublicKey, SecretKey), Error> {
            let mut seed = [0u8; KEYGEN_SEED_LEN];
            rng.try_fill_bytes(&mut seed)
                .map_err(|_| Error::RngFailure)?;
            keygen_with_seed(&seed)
        }

        fn keygen_with_seed(seed: &[u8; KEYGEN_SEED_LEN]) -> Result<(PublicKey, SecretKey), Error> {
            let (pk, sk) = $crate::sign::keygen::<$params>(seed);
            Ok((PublicKey { pk }, SecretKey { sk }))
        }

        #[doc = concat!("Sign a message using ", $doc_variant, " with system randomness.")]
        pub fn sign(
            sk: &SecretKey,
            msg: &[u8],
            context: Option<&[u8]>,
            hash_algorithm: Option<HashAlgorithm>,
        ) -> Result<Signature, Error> {
            let mut rnd = [0u8; 32];
            getrandom::getrandom(&mut rnd).map_err(|_| Error::RngFailure)?;
            sign_with_rnd(sk, msg, &rnd, context, hash_algorithm)
        }

        #[doc = concat!("Sign a message using ", $doc_variant, " with a caller-provided RNG.")]
        #[doc = "Draws the 32-byte randomizer `rnd` from `rng`."]
        pub fn sign_with_rng(
            sk: &SecretKey,
            msg: &[u8],
            rng: &mut impl CryptoRngCore,
            context: Option<&[u8]>,
            hash_algorithm: Option<HashAlgorithm>,
        ) -> Result<Signature, Error> {
            let mut rnd = [0u8; 32];
            rng.try_fill_bytes(&mut rnd)
                .map_err(|_| Error::RngFailure)?;
            sign_with_rnd(sk, msg, &rnd, context, hash_algorithm)
        }

        fn sign_with_rnd(
            sk: &SecretKey,
            msg: &[u8],
            rnd: &[u8; 32],
            context: Option<&[u8]>,
            hash_algorithm: Option<HashAlgorithm>,
        ) -> Result<Signature, Error> {
            let (prefix, msg_inner) = match hash_algorithm {
                Some(o) => {
                    // FIPS 204 §5.4.1 (Alg. 4): the HashML-DSA message input is
                    // M' = 0x01 ∥ ctx_len ∥ ctx ∥ OID ∥ H(M) with NO leading
                    // 0x00 ∥ 0x00, so mu = H(tr ∥ M') via an empty prefix.
                    let m = $crate::sign::domain_prefix(
                        context.unwrap_or(&[]),
                        Some((o.der_bytes(), msg)),
                    )?;
                    (Vec::new(), m)
                }
                None => {
                    let prefix = match context {
                        Some(c) => $crate::sign::domain_prefix(c, None)?,
                        None => vec![0u8, 0u8],
                    };
                    (prefix, msg.to_vec())
                }
            };
            let sig = $crate::sign::sign::<$params>(sk.as_ref(), &msg_inner, &prefix, rnd)?;
            Ok(Signature { sig })
        }

        #[doc = concat!("Verify a ", $doc_variant, " signature.")]
        pub fn verify(
            pk: &PublicKey,
            msg: &[u8],
            signature: &Signature,
            context: Option<&[u8]>,
            hash_algorithm: Option<HashAlgorithm>,
        ) -> Result<(), Error> {
            if pk.pk.len() != <$params as Params>::PK_BYTES {
                return Err(Error::InvalidKeyLength);
            }
            if signature.sig.len() != <$params as Params>::SIG_BYTES {
                return Err(Error::InvalidSignatureLength);
            }
            let (prefix, msg_inner) = match hash_algorithm {
                Some(o) => {
                    // FIPS 204 §5.4.1 (Alg. 4): the HashML-DSA message input is
                    // M' = 0x01 ∥ ctx_len ∥ ctx ∥ OID ∥ H(M) with NO leading
                    // 0x00 ∥ 0x00, so mu = H(tr ∥ M') via an empty prefix.
                    let m = $crate::sign::domain_prefix(
                        context.unwrap_or(&[]),
                        Some((o.der_bytes(), msg)),
                    )?;
                    (Vec::new(), m)
                }
                None => {
                    let prefix = match context {
                        Some(c) => $crate::sign::domain_prefix(c, None)?,
                        None => vec![0u8, 0u8],
                    };
                    (prefix, msg.to_vec())
                }
            };
            if $crate::sign::verify_with_prefix::<$params>(
                &pk.pk,
                &msg_inner,
                &prefix,
                &signature.sig,
            ) {
                Ok(())
            } else {
                Err(Error::InvalidSignature)
            }
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
        impl AsRef<[u8]> for Signature {
            fn as_ref(&self) -> &[u8] {
                &self.sig
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

        impl TryFrom<&[u8]> for Signature {
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
                let seed = b"0123456789abcdef0123456789abcdef";
                let (pk1, sk1) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                let (pk2, sk2) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                assert_eq!(pk1.pk, pk2.pk);
                assert_eq!(sk1.as_ref(), sk2.as_ref());
            }

            #[test]
            fn test_keygen_different_seeds() {
                let (pk1, _) = keygen_with_rng(&mut FixedRng::new(
                    b"seed1234567890123456789012345678".to_vec(),
                ))
                .unwrap();
                let (pk2, _) = keygen_with_rng(&mut FixedRng::new(
                    b"SEED1234567890123456789012345678".to_vec(),
                ))
                .unwrap();
                assert_ne!(pk1.pk, pk2.pk);
            }

            #[test]
            fn test_sign_verify_roundtrip() {
                let seed = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                let msg = b"post-quantum ready";
                let sig =
                    sign_with_rng(&sk, msg, &mut FixedRng::new(vec![0u8; 32]), None, None).unwrap();
                assert!(verify(&pk, msg, &sig, None, None).is_ok());
            }

            #[test]
            fn test_verify_wrong_message() {
                let seed = b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                let sig = sign_with_rng(
                    &sk,
                    b"original message",
                    &mut FixedRng::new(vec![0u8; 32]),
                    None,
                    None,
                )
                .unwrap();
                assert!(verify(&pk, b"wrong message", &sig, None, None).is_err());
            }

            #[test]
            fn test_verify_wrong_key() {
                let seed_a = b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
                let seed_b = b"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
                let (pk_a, _) = keygen_with_rng(&mut FixedRng::new(seed_a.to_vec())).unwrap();
                let (_, sk_b) = keygen_with_rng(&mut FixedRng::new(seed_b.to_vec())).unwrap();
                let sig =
                    sign_with_rng(&sk_b, b"msg", &mut FixedRng::new(vec![0u8; 32]), None, None)
                        .unwrap();
                assert!(verify(&pk_a, b"msg", &sig, None, None).is_err());
            }

            #[test]
            fn test_negative_corrupted_sig() {
                let seed = b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                let msg = b"hello ml-dsa negative test";
                let sig = sign(&sk, msg, None, None).unwrap();
                assert!(verify(&pk, msg, &sig, None, None).is_ok());
                let mut bad_bytes = sig.sig.clone();
                let corrupt_idx = 40 % bad_bytes.len();
                bad_bytes[corrupt_idx] ^= 0x01;
                let bad_sig = Signature { sig: bad_bytes };
                assert!(
                    verify(&pk, msg, &bad_sig, None, None).is_err(),
                    "verify should reject corrupted sig"
                );
            }

            #[test]
            fn test_negative_truncated_sig() {
                let seed = b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                let msg = b"hello ml-dsa negative test";
                let sig = sign(&sk, msg, None, None).unwrap();
                assert!(verify(&pk, msg, &sig, None, None).is_ok());
                let empty_sig = Signature { sig: vec![] };
                assert!(
                    verify(&pk, msg, &empty_sig, None, None).is_err(),
                    "verify should reject empty sig"
                );
                let half_sig = Signature {
                    sig: sig.sig[..sig.sig.len() / 2].to_vec(),
                };
                assert!(
                    verify(&pk, msg, &half_sig, None, None).is_err(),
                    "verify should reject truncated sig"
                );
            }

            #[test]
            fn test_negative_empty_msg() {
                let seed = b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed.to_vec())).unwrap();
                let msg = b"";
                let sig = sign(&sk, msg, None, None).unwrap();
                assert!(
                    verify(&pk, msg, &sig, None, None).is_ok(),
                    "empty message should verify"
                );
            }
        }
    };
}
