/// Macro to generate the public API for an SPHINCS+ variant module.
///
/// Generates `PublicKey`, `SecretKey`, `Signature` types along with
/// `keygen`, `keygen_with_rng`, `sign`, `sign_with_rng`, `verify` public functions.
///
/// `$param_type`: A type implementing `ConstParams` (e.g. `Sha2_128f`).
#[macro_export]
macro_rules! define_variant {
    ($param_type:ident) => {
        use alloc::vec::Vec;
        use backbone_pqcrypto_internals::oid::HashAlgorithm;
        use backbone_pqcrypto_internals::secret::{SecretArray, SecretVec};
        use $crate::error::Error;
        use $crate::params::$param_type as Params;
        use $crate::params::ConstParams;
        use $crate::rand_core::CryptoRngCore;
        use $crate::sphincs::slh_keygen;
        use $crate::sphincs::slh_sign_internal;
        use $crate::sphincs::slh_verify_internal;
        use zeroize::Zeroize;

        /// Public key.
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct PublicKey {
            /// Raw public key bytes (pk_seed ∥ pk_root).
            pub pk: Vec<u8>,
        }

        /// Secret key.
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

        /// Signature.
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct Signature {
            /// Raw signature bytes.
            pub sig: Vec<u8>,
        }

        impl PublicKey {
            /// Construct from raw bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <Params as ConstParams>::PK_BYTES {
                    return Err(Error::InvalidKeyLength);
                }
                Ok(Self { pk: bytes.to_vec() })
            }
        }

        impl SecretKey {
            /// Construct from raw bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <Params as ConstParams>::SK_BYTES {
                    return Err(Error::InvalidSecretKeyLength);
                }
                Ok(Self { sk: bytes.to_vec() })
            }
        }

        impl Signature {
            /// Construct from raw bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <Params as ConstParams>::SIG_BYTES {
                    return Err(Error::InvalidSignatureLength);
                }
                Ok(Self {
                    sig: bytes.to_vec(),
                })
            }
        }

        // ------------------------------------------------------------------
        // SLH-DSA message formatting (FIPS-205 Section 10.2)
        // ------------------------------------------------------------------

        /// Format a message for context-mode SLH-DSA (FIPS 205 Section 10.2).
        /// Produces: 0x00 ∥ ctx_len ∥ ctx ∥ M
        /// Does NOT short-circuit on empty context — even an empty context
        /// is formatted as 0x00 ∥ 0x00 ∥ M for the external API.
        fn format_slh_message(context: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
            if context.len() > 255 {
                return Err(Error::InvalidContextLength);
            }
            let mut formatted = Vec::with_capacity(2 + context.len() + msg.len());
            formatted.push(0);
            formatted.push(u8::try_from(context.len()).map_err(|_| Error::InvalidContextLength)?);
            formatted.extend_from_slice(context);
            formatted.extend_from_slice(msg);
            Ok(formatted)
        }

        /// Format message for Hash-SLH-DSA (pre-hash mode).
        /// M' = 0x01 ∥ ctx_len ∥ ctx ∥ OID ∥ H
        fn format_hash_slh_message(
            context: &[u8],
            prehash_oid: &[u8],
            prehash: &[u8],
        ) -> Result<Vec<u8>, Error> {
            if context.len() > 255 {
                return Err(Error::InvalidContextLength);
            }
            let mut formatted =
                Vec::with_capacity(2 + context.len() + prehash_oid.len() + prehash.len());
            formatted.push(1);
            formatted.push(u8::try_from(context.len()).map_err(|_| Error::InvalidContextLength)?);
            formatted.extend_from_slice(context);
            formatted.extend_from_slice(prehash_oid);
            formatted.extend_from_slice(prehash);
            Ok(formatted)
        }

        // ------------------------------------------------------------------
        // Public API
        // ------------------------------------------------------------------

        /// Generate an SPHINCS+ keypair using system randomness.
        pub fn keygen() -> Result<(PublicKey, SecretKey), Error> {
            let mut seed = SecretArray::<u8, { <Params as ConstParams>::SEED_BYTES }>::new();
            getrandom::getrandom(seed.as_mut()).map_err(|_| Error::RngFailure)?;
            keygen_with_seed(seed.as_ref())
        }

        /// Generate an SPHINCS+ keypair using a caller-provided RNG.
        ///
        /// Draws exactly [`ConstParams::SEED_BYTES`] bytes from `rng`
        /// (`sk_seed || sk_prf || pk_seed`).
        pub fn keygen_with_rng(
            rng: &mut impl CryptoRngCore,
        ) -> Result<(PublicKey, SecretKey), Error> {
            let mut seed = SecretArray::<u8, { <Params as ConstParams>::SEED_BYTES }>::new();
            rng.try_fill_bytes(seed.as_mut())
                .map_err(|_| Error::RngFailure)?;
            keygen_with_seed(seed.as_ref())
        }

        fn keygen_with_seed(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error> {
            let n = <Params as ConstParams>::N;
            let sk_seed = &seed[..n];
            let sk_prf = &seed[n..2 * n];
            let pk_seed = &seed[2 * n..3 * n];

            let (vk_bytes, sk_bytes) = slh_keygen::<Params>(sk_seed, sk_prf, pk_seed)?;
            Ok((PublicKey { pk: vk_bytes }, SecretKey { sk: sk_bytes }))
        }

        /// Sign a message (randomized).
        ///
        /// * `context` — domain separation context (max 255 bytes).
        ///   `None` means pure mode.
        pub fn sign(
            sk: &SecretKey,
            msg: &[u8],
            context: Option<&[u8]>,
            hash_algorithm: Option<HashAlgorithm>,
        ) -> Result<Signature, Error> {
            let n = <Params as ConstParams>::N;
            let mut optrand = SecretVec::<u8>::new(n);
            getrandom::getrandom(&mut optrand).map_err(|_| Error::RngFailure)?;
            sign_with_optrand(sk, msg, &optrand, context, hash_algorithm)
        }

        /// Sign a message with a caller-provided RNG.
        ///
        /// Draws the `n`-byte randomizer `optrand` from `rng`.
        pub fn sign_with_rng(
            sk: &SecretKey,
            msg: &[u8],
            rng: &mut impl CryptoRngCore,
            context: Option<&[u8]>,
            hash_algorithm: Option<HashAlgorithm>,
        ) -> Result<Signature, Error> {
            let n = <Params as ConstParams>::N;
            let mut optrand = SecretVec::<u8>::new(n);
            rng.try_fill_bytes(&mut optrand)
                .map_err(|_| Error::RngFailure)?;
            sign_with_optrand(sk, msg, &optrand, context, hash_algorithm)
        }

        fn sign_with_optrand(
            sk: &SecretKey,
            msg: &[u8],
            optrand: &[u8],
            context: Option<&[u8]>,
            hash_algorithm: Option<HashAlgorithm>,
        ) -> Result<Signature, Error> {
            let formatted = match (context, hash_algorithm) {
                // FIPS 205 §10.2.1 (Alg. 22): pure mode prepends the domain
                // separator 0x00 ∥ ctx_len ∥ ctx (empty context: 0x00 ∥ 0x00).
                (None, None) => format_slh_message(&[], msg)?,
                (Some(ctx), None) => format_slh_message(ctx, msg)?,
                (None, Some(alg)) => format_hash_slh_message(
                    &[],
                    alg.der_bytes(),
                    &$crate::sphincs::prehash_message(alg, msg),
                )?,
                (Some(ctx), Some(alg)) => format_hash_slh_message(
                    ctx,
                    alg.der_bytes(),
                    &$crate::sphincs::prehash_message(alg, msg),
                )?,
            };
            internal_sign(sk, &formatted, optrand)
        }

        fn internal_sign(
            sk: &SecretKey,
            formatted: &[u8],
            optrand: &[u8],
        ) -> Result<Signature, Error> {
            let sig_bytes =
                slh_sign_internal::<Params>(sk.sk.as_slice(), formatted, Some(optrand))?;
            Ok(Signature { sig: sig_bytes })
        }

        /// Verify a signature.
        ///
        /// * `context` — domain separation context. Must match what was used during signing.
        ///   `None` means pure mode.
        pub fn verify(
            pk: &PublicKey,
            msg: &[u8],
            signature: &Signature,
            context: Option<&[u8]>,
            hash_algorithm: Option<HashAlgorithm>,
        ) -> Result<(), Error> {
            if pk.pk.len() != <Params as ConstParams>::PK_BYTES {
                return Err(Error::InvalidKeyLength);
            }
            if signature.sig.len() != <Params as ConstParams>::SIG_BYTES {
                return Err(Error::InvalidSignatureLength);
            }
            let formatted = match (context, hash_algorithm) {
                // FIPS 205 §10.2.1 (Alg. 22): pure mode prepends the domain
                // separator 0x00 ∥ ctx_len ∥ ctx (empty context: 0x00 ∥ 0x00).
                (None, None) => format_slh_message(&[], msg)?,
                (Some(ctx), None) => format_slh_message(ctx, msg)?,
                (None, Some(alg)) => format_hash_slh_message(
                    &[],
                    alg.der_bytes(),
                    &$crate::sphincs::prehash_message(alg, msg),
                )?,
                (Some(ctx), Some(alg)) => format_hash_slh_message(
                    ctx,
                    alg.der_bytes(),
                    &$crate::sphincs::prehash_message(alg, msg),
                )?,
            };

            if slh_verify_internal::<Params>(
                pk.pk.as_slice(),
                &formatted,
                signature.sig.as_slice(),
            )? {
                Ok(())
            } else {
                Err(Error::InvalidSignature)
            }
        }

        // ------------------------------------------------------------------
        // AsRef impls
        // ------------------------------------------------------------------

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

        // ------------------------------------------------------------------
        // Inline unit tests
        // ------------------------------------------------------------------

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
            use alloc::vec;
            use backbone_pqcrypto_internals::kat::FixedRng;

            const N: usize = <Params as ConstParams>::N;
            const SEED_SIZE: usize = <Params as ConstParams>::SEED_BYTES;

            #[test]
            fn test_keygen_with_rng() {
                let seed = vec![0x42u8; SEED_SIZE];
                let (pk1, sk1) = keygen_with_rng(&mut FixedRng::new(seed.clone())).unwrap();
                let (pk2, sk2) = keygen_with_rng(&mut FixedRng::new(seed)).unwrap();
                assert_eq!(pk1.pk, pk2.pk);
                assert_eq!(sk1.as_ref(), sk2.as_ref());
            }

            #[test]
            fn test_keygen_different_seeds() {
                let (pk1, _) =
                    keygen_with_rng(&mut FixedRng::new(vec![0x12u8; SEED_SIZE])).unwrap();
                let (pk2, _) =
                    keygen_with_rng(&mut FixedRng::new(vec![0x34u8; SEED_SIZE])).unwrap();
                assert_ne!(pk1.pk, pk2.pk);
            }

            #[test]
            fn test_sign_verify_roundtrip() {
                let seed = vec![0x42u8; SEED_SIZE];
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed)).unwrap();
                let msg = b"post-quantum ready";
                let sig =
                    sign_with_rng(&sk, msg, &mut FixedRng::new(vec![0u8; N]), None, None).unwrap();
                assert!(verify(&pk, msg, &sig, None, None).is_ok());
            }

            #[test]
            fn test_verify_wrong_message() {
                let seed = vec![0x42u8; SEED_SIZE];
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(seed)).unwrap();
                let sig = sign_with_rng(
                    &sk,
                    b"original message",
                    &mut FixedRng::new(vec![0u8; N]),
                    None,
                    None,
                )
                .unwrap();
                assert!(verify(&pk, b"wrong message", &sig, None, None).is_err());
            }

            #[test]
            fn test_verify_wrong_key() {
                let (pk_a, _) =
                    keygen_with_rng(&mut FixedRng::new(vec![0x42u8; SEED_SIZE])).unwrap();
                let (_, sk_b) =
                    keygen_with_rng(&mut FixedRng::new(vec![0xabu8; SEED_SIZE])).unwrap();
                let sig =
                    sign_with_rng(&sk_b, b"msg", &mut FixedRng::new(vec![0u8; N]), None, None)
                        .unwrap();
                assert!(verify(&pk_a, b"msg", &sig, None, None).is_err());
            }
        }
    };
}
