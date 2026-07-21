/// Generate a full SPHINCS+ variant module (PublicKey, SecretKey, Signature,
/// keygen, sign, verify, AsRef impls, and tests).
///
/// `$param_type` must be a params type like `Sha2_128f` or `Shake128f`
/// defined in `crate::params`.
#[macro_export]
macro_rules! define_variant {
    ($param_type:ident) => {
        use $crate::error::Error;
        use $crate::params::$param_type;
        use $crate::params::Params;
        use alloc::vec::Vec;
        use sha3::{digest::ExtendableOutput, digest::Update, digest::XofReader, Shake256};
        #[cfg(feature = "zeroize")]
        use zeroize::Zeroize;

        #[doc = concat!("Public key for ", stringify!($param_type), ".")]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct PublicKey {
            /// Raw public key bytes.
            pub pk: Vec<u8>,
        }

        #[doc = concat!("Secret key for ", stringify!($param_type), ".")]
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

        #[doc = concat!("Signature for ", stringify!($param_type), ".")]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct Signature {
            /// Raw signature bytes.
            pub sig: Vec<u8>,
        }

        impl PublicKey {
            #[doc = concat!("Construct a ", stringify!($param_type), " public key from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <$param_type as Params>::PK_BYTES {
                    return Err(Error::InvalidKeyLength);
                }
                Ok(Self { pk: bytes.to_vec() })
            }
        }

        impl SecretKey {
            #[doc = concat!("Construct a ", stringify!($param_type), " secret key from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <$param_type as Params>::SK_BYTES {
                    return Err(Error::InvalidSecretKeyLength);
                }
                Ok(Self { sk: bytes.to_vec() })
            }

            /// Return the secret key bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.sk
            }
        }

        impl Signature {
            #[doc = concat!("Construct a ", stringify!($param_type), " signature from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <$param_type as Params>::SIG_BYTES {
                    return Err(Error::InvalidSignatureLength);
                }
                Ok(Self { sig: bytes.to_vec() })
            }
        }

        #[doc = concat!("Generate a ", stringify!($param_type), " keypair deterministically from a seed.")]
        pub fn keygen(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error> {
            if seed.len() != <$param_type as Params>::SEED_BYTES {
                return Err(Error::InvalidSeedLength);
            }
            let (pk, sk) = $crate::sign::keygen::<$param_type>(seed);
            Ok((PublicKey { pk }, SecretKey { sk }))
        }

        #[doc = concat!("Generate a ", stringify!($param_type), " keypair from an exact-length seed.")]
        pub fn keygen_checked(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error> {
            let (pk, sk) = $crate::sign::keygen_checked::<$param_type>(seed)?;
            Ok((PublicKey { pk }, SecretKey { sk }))
        }

        #[doc = concat!("Generate a keypair from a seed (alias for keygen) — ", stringify!($param_type), ".")]
        pub fn keypair_from_seed(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error> {
            keygen(seed)
        }

        #[doc = concat!("Generate a keypair from an exact-length seed — ", stringify!($param_type), ".")]
        pub fn keypair_from_seed_checked(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error> {
            keygen_checked(seed)
        }

        // -----------------------------------------------------------------------
        // Internal helpers (submission API — raw, no FIPS 205 prefix)
        // -----------------------------------------------------------------------

        fn _sign_deterministic_submission(
            sk: &SecretKey,
            msg: &[u8],
            seed: &[u8],
        ) -> Result<Signature, Error> {
            let sig = $crate::sign::sign::<$param_type>(sk.as_ref(), msg, seed)?;
            Ok(Signature { sig })
        }

        fn _verify_submission(pk: &PublicKey, msg: &[u8], signature: &Signature) -> bool {
            $crate::sign::verify::<$param_type>(&pk.pk, msg, &signature.sig)
        }

        // -----------------------------------------------------------------------
        // Signing — FIPS 205 SLH-DSA API
        // -----------------------------------------------------------------------

        #[doc = concat!("Sign a message using ", stringify!($param_type), " (FIPS 205 SLH-DSA).")]
        ///
        /// Uses system randomness for the optional randomizer `optrand`.
        /// The message is wrapped with an empty context prefix per FIPS 205.
        pub fn sign(sk: &SecretKey, msg: &[u8]) -> Result<Signature, Error> {
            let mut seed = alloc::vec![0u8; <$param_type as Params>::N];
            getrandom::getrandom(&mut seed).map_err(|_| Error::RngFailure)?;
            let formatted = format_slh_message(&[], msg)?;
            _sign_deterministic_submission(sk, &formatted, &seed)
        }

        #[doc = concat!("Sign a message using ", stringify!($param_type), " (submission API — no FIPS 205 prefix).")]
        ///
        /// Uses system randomness for the optional randomizer `optrand`.
        pub fn sign_submission(sk: &SecretKey, msg: &[u8]) -> Result<Signature, Error> {
            let mut seed = alloc::vec![0u8; <$param_type as Params>::N];
            getrandom::getrandom(&mut seed).map_err(|_| Error::RngFailure)?;
            _sign_deterministic_submission(sk, msg, &seed)
        }

        #[doc = concat!("Sign a message using ", stringify!($param_type), " with a specific seed (FIPS 205 SLH-DSA).")]
        ///
        /// The `seed` is used as the optional randomizer `optrand` (FIPS 205).
        /// The message is wrapped with an empty context prefix per FIPS 205.
        pub fn sign_deterministic(
            sk: &SecretKey,
            msg: &[u8],
            seed: &[u8],
        ) -> Result<Signature, Error> {
            let formatted = format_slh_message(&[], msg)?;
            _sign_deterministic_submission(sk, &formatted, seed)
        }

        #[doc = concat!("Sign a message using ", stringify!($param_type), " with a specific seed (submission API — no FIPS 205 prefix).")]
        ///
        /// The `seed` is used as the optional randomizer `optrand`.
        pub fn sign_deterministic_submission(
            sk: &SecretKey,
            msg: &[u8],
            seed: &[u8],
        ) -> Result<Signature, Error> {
            _sign_deterministic_submission(sk, msg, seed)
        }

        #[doc = concat!("Sign a message using ", stringify!($param_type), " with a FIPS 205 context.")]
        pub fn sign_with_context(
            sk: &SecretKey,
            msg: &[u8],
            ctx: &[u8],
        ) -> Result<Signature, Error> {
            let mut seed = alloc::vec![0u8; <$param_type as Params>::N];
            getrandom::getrandom(&mut seed).map_err(|_| Error::RngFailure)?;
            sign_deterministic_with_context(sk, msg, ctx, &seed)
        }

        #[doc = concat!("Sign a message using ", stringify!($param_type), " with a FIPS 205 context and specific optrand.")]
        pub fn sign_deterministic_with_context(
            sk: &SecretKey,
            msg: &[u8],
            ctx: &[u8],
            seed: &[u8],
        ) -> Result<Signature, Error> {
            let formatted = format_slh_message(ctx, msg)?;
            _sign_deterministic_submission(sk, &formatted, seed)
        }

        #[doc = concat!("Sign a prehashed message using ", stringify!($param_type), " with a FIPS 205 context and OID.")]
        pub fn sign_prehashed_with_context(
            sk: &SecretKey,
            prehash_oid: &[u8],
            prehash: &[u8],
            ctx: &[u8],
            seed: &[u8],
        ) -> Result<Signature, Error> {
            let formatted = format_hash_slh_message(ctx, prehash_oid, prehash)?;
            _sign_deterministic_submission(sk, &formatted, seed)
        }

        #[doc = concat!("Sign a message with HashSLH-DSA-SHAKE-256 using ", stringify!($param_type), ".")]
        pub fn sign_prehashed_shake256_with_context(
            sk: &SecretKey,
            msg: &[u8],
            ctx: &[u8],
            seed: &[u8],
        ) -> Result<Signature, Error> {
            let mut ph = [0u8; 64];
            let mut shake = Shake256::default();
            shake.update(msg);
            let mut reader = shake.finalize_xof();
            reader.read(&mut ph);
            sign_prehashed_with_context(sk, &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c], &ph, ctx, seed)
        }

        // -----------------------------------------------------------------------
        // Verification — FIPS 205 SLH-DSA API
        // -----------------------------------------------------------------------

        #[doc = concat!("Verify a ", stringify!($param_type), " signature (FIPS 205 SLH-DSA).")]
        #[must_use]
        pub fn verify(pk: &PublicKey, msg: &[u8], signature: &Signature) -> bool {
            let Ok(formatted) = format_slh_message(&[], msg) else {
                return false;
            };
            _verify_submission(pk, &formatted, signature)
        }

        #[doc = concat!("Verify a ", stringify!($param_type), " signature (submission API — no FIPS 205 prefix).")]
        #[must_use]
        pub fn verify_submission(pk: &PublicKey, msg: &[u8], signature: &Signature) -> bool {
            _verify_submission(pk, msg, signature)
        }

        #[doc = concat!("Verify a ", stringify!($param_type), " signature and return a validation error on malformed raw input.")]
        pub fn verify_result(pk: &PublicKey, msg: &[u8], signature: &Signature) -> Result<(), Error> {
            if pk.pk.len() != <$param_type as Params>::PK_BYTES {
                return Err(Error::InvalidKeyLength);
            }
            if signature.sig.len() != <$param_type as Params>::SIG_BYTES {
                return Err(Error::InvalidSignatureLength);
            }
            if verify(pk, msg, signature) {
                Ok(())
            } else {
                Err(Error::InvalidSignature)
            }
        }

        #[doc = concat!("Verify a ", stringify!($param_type), " signature with a FIPS 205 context.")]
        #[must_use]
        pub fn verify_with_context(
            pk: &PublicKey,
            msg: &[u8],
            signature: &Signature,
            ctx: &[u8],
        ) -> bool {
            let Ok(formatted) = format_slh_message(ctx, msg) else {
                return false;
            };
            _verify_submission(pk, &formatted, signature)
        }

        #[doc = concat!("Verify a prehashed ", stringify!($param_type), " signature with a FIPS 205 context and OID.")]
        #[must_use]
        pub fn verify_prehashed_with_context(
            pk: &PublicKey,
            prehash_oid: &[u8],
            prehash: &[u8],
            signature: &Signature,
            ctx: &[u8],
        ) -> bool {
            let Ok(formatted) = format_hash_slh_message(ctx, prehash_oid, prehash) else {
                return false;
            };
            _verify_submission(pk, &formatted, signature)
        }

        #[doc = concat!("Verify a HashSLH-DSA-SHAKE-256 signature using ", stringify!($param_type), ".")]
        #[must_use]
        pub fn verify_prehashed_shake256_with_context(
            pk: &PublicKey,
            msg: &[u8],
            signature: &Signature,
            ctx: &[u8],
        ) -> bool {
            let mut ph = [0u8; 64];
            let mut shake = Shake256::default();
            shake.update(msg);
            let mut reader = shake.finalize_xof();
            reader.read(&mut ph);
            verify_prehashed_with_context(pk, &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c], &ph, signature, ctx)
        }

        fn format_slh_message(ctx: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
            if ctx.len() > 255 {
                return Err(Error::InvalidContextLength);
            }
            let mut formatted = Vec::with_capacity(2 + ctx.len() + msg.len());
            formatted.push(0);
            formatted.push(u8::try_from(ctx.len()).expect("ctx length is <= 255"));
            formatted.extend_from_slice(ctx);
            formatted.extend_from_slice(msg);
            Ok(formatted)
        }

        fn format_hash_slh_message(
            ctx: &[u8],
            prehash_oid: &[u8],
            prehash: &[u8],
        ) -> Result<Vec<u8>, Error> {
            if ctx.len() > 255 {
                return Err(Error::InvalidContextLength);
            }
            let mut formatted = Vec::with_capacity(2 + ctx.len() + prehash_oid.len() + prehash.len());
            formatted.push(1);
            formatted.push(u8::try_from(ctx.len()).expect("ctx length is <= 255"));
            formatted.extend_from_slice(ctx);
            formatted.extend_from_slice(prehash_oid);
            formatted.extend_from_slice(prehash);
            Ok(formatted)
        }

        // -----------------------------------------------------------------------
        // AsRef impls
        // -----------------------------------------------------------------------

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

        #[cfg(test)]
        mod tests {
            use super::*;

            const SEED_SIZE: usize =
                <$crate::params::$param_type as $crate::params::Params>::SEED_BYTES;

            #[test]
            fn test_keygen_deterministic() {
                let seed = [0x42u8; SEED_SIZE];
                let (pk1, sk1) = keygen(&seed).unwrap();
                let (pk2, sk2) = keygen(&seed).unwrap();
                assert_eq!(pk1.pk, pk2.pk);
                assert_eq!(sk1.as_ref(), sk2.as_ref());
            }

            #[test]
            fn test_keygen_different_seeds() {
                let (pk1, _) = keygen(&[0x12u8; SEED_SIZE]).unwrap();
                let (pk2, _) = keygen(&[0x34u8; SEED_SIZE]).unwrap();
                assert_ne!(pk1.pk, pk2.pk);
            }

            #[test]
            fn test_sign_verify_roundtrip() {
                let seed = [0x42u8; SEED_SIZE];
                let (pk, sk) = keygen(&seed).unwrap();
                let msg = b"post-quantum ready";
                let sig = sign(&sk, msg).unwrap();
                assert!(verify(&pk, msg, &sig));
            }

            #[test]
            fn test_verify_wrong_message() {
                let seed = [0x42u8; SEED_SIZE];
                let (pk, sk) = keygen(&seed).unwrap();
                let sig = sign(&sk, b"original message").unwrap();
                assert!(!verify(&pk, b"wrong message", &sig));
            }

            #[test]
            fn test_verify_wrong_key() {
                let (pk_a, _) = keygen(&[0x42u8; SEED_SIZE]).unwrap();
                let (_, sk_b) = keygen(&[0xabu8; SEED_SIZE]).unwrap();
                let sig = sign(&sk_b, b"msg").unwrap();
                assert!(!verify(&pk_a, b"msg", &sig));
            }
        }
    };
}
