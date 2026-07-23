/// Macro to generate the public API for an ML-DSA variant module.
///
/// Generates `PublicKey`, `SecretKey`, `Signature` types, along with
/// `keygen`, `keypair_from_seed`, `sign`, `sign_deterministic`, `verify`,
/// `AsRef` impls, and inline tests.
///
/// `$params`: The Params implementor (e.g. `Mldsa44`).
/// `$doc_variant`: Display name for doc comments (e.g. `"ML-DSA-44"`).
/// `$doc_sec`: Security category (e.g. `"1"`).
#[macro_export]
macro_rules! define_variant {
    ($params:ident, $doc_variant:expr, $doc_sec:expr) => {
        use alloc::vec::Vec;
        use $crate::error::Error;
        use $crate::params::$params;
        use $crate::params::Params;
        use sha3::{digest::ExtendableOutput, digest::Update, digest::XofReader, Shake256};
        #[cfg(feature = "zeroize")]
        use zeroize::Zeroize;

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

        #[doc = concat!($doc_variant, " public key.")]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct PublicKey {
            pub pk: Vec<u8>,
        }

        #[doc = concat!($doc_variant, " signature.")]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct Signature {
            pub sig: Vec<u8>,
        }

        impl SecretKey {
            #[doc = concat!("Construct an ", $doc_variant, " secret key from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <$params as Params>::SECRET_KEY_BYTES {
                    return Err(Error::InvalidSecretKeyLength);
                }
                Ok(Self { sk: bytes.to_vec() })
            }

            #[doc = concat!("Return the raw ", $doc_variant, " secret key bytes.")]
            pub fn as_bytes(&self) -> &[u8] {
                &self.sk
            }
        }

        impl PublicKey {
            #[doc = concat!("Construct an ", $doc_variant, " public key from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <$params as Params>::PUBLIC_KEY_BYTES {
                    return Err(Error::InvalidKeyLength);
                }
                Ok(Self { pk: bytes.to_vec() })
            }
        }

        impl Signature {
            #[doc = concat!("Construct an ", $doc_variant, " signature from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != <$params as Params>::SIGNATURE_BYTES {
                    return Err(Error::InvalidSignatureLength);
                }
                Ok(Self { sig: bytes.to_vec() })
            }
        }

        #[doc = concat!("Generate an ", $doc_variant, " keypair deterministically from a 32-byte seed.")]
        pub fn keygen(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error> {
            if seed.len() != 32 {
                return Err(Error::InvalidSeedLength);
            }
            let (pk, sk) = $crate::sign::keygen::<$params>(seed);
            Ok((PublicKey { pk }, SecretKey { sk }))
        }

        #[doc = concat!("Generate an ", $doc_variant, " keypair from a 32-byte seed.")]
        pub fn keygen_checked(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error> {
            keygen(seed)
        }

        pub fn keypair_from_seed(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error> {
            keygen(seed)
        }

        pub fn keypair_from_seed_checked(seed: &[u8]) -> Result<(PublicKey, SecretKey), Error> {
            keygen_checked(seed)
        }

        #[doc = concat!("Sign a message using ", $doc_variant, ".")]
        pub fn sign(sk: &SecretKey, msg: &[u8]) -> Result<Signature, Error> {
            let mut rnd = [0u8; 32];
            getrandom::getrandom(&mut rnd).map_err(|_| Error::RngFailure)?;
            let sig = $crate::sign::sign::<$params>(sk.as_ref(), msg, &[0u8, 0u8], &rnd)?;
            Ok(Signature { sig })
        }

        #[doc = concat!("Sign a message using ", $doc_variant, " in pure mode.")]
        pub fn sign_pure(sk: &SecretKey, msg: &[u8]) -> Result<Signature, Error> {
            sign(sk, msg)
        }

        #[doc = concat!("Sign a message using ", $doc_variant, " with a specific seed.")]
        pub fn sign_deterministic(
            sk: &SecretKey,
            msg: &[u8],
            seed: &[u8],
        ) -> Result<Signature, Error> {
            let rnd: [u8; 32] = seed.try_into().map_err(|_| Error::InvalidSeedLength)?;
            let sig = $crate::sign::sign::<$params>(sk.as_ref(), msg, &[0u8, 0u8], &rnd)?;
            Ok(Signature { sig })
        }

        #[doc = concat!("Sign a message using ", $doc_variant, " in pure deterministic mode.")]
        pub fn sign_deterministic_pure(
            sk: &SecretKey,
            msg: &[u8],
            seed: &[u8],
        ) -> Result<Signature, Error> {
            sign_deterministic(sk, msg, seed)
        }

        #[doc = concat!("Sign a message using ", $doc_variant, " with a FIPS 204 context.")]
        pub fn sign_with_context(
            sk: &SecretKey,
            msg: &[u8],
            ctx: &[u8],
        ) -> Result<Signature, Error> {
            let mut rnd = [0u8; 32];
            getrandom::getrandom(&mut rnd).map_err(|_| Error::RngFailure)?;
            sign_deterministic_with_context(sk, msg, ctx, &rnd)
        }

        #[doc = concat!("Sign a message using ", $doc_variant, " with a FIPS 204 context and specific randomness.")]
        pub fn sign_deterministic_with_context(
            sk: &SecretKey,
            msg: &[u8],
            ctx: &[u8],
            seed: &[u8],
        ) -> Result<Signature, Error> {
            let rnd: [u8; 32] = seed.try_into().map_err(|_| Error::InvalidSeedLength)?;
            let prefix = $crate::sign::domain_prefix(ctx, None)?;
            let sig = $crate::sign::sign::<$params>(sk.as_ref(), msg, &prefix, &rnd)?;
            Ok(Signature { sig })
        }

        #[doc = concat!("Sign a prehashed message using ", $doc_variant, " with a FIPS 204 context and OID.")]
        pub fn sign_prehashed_with_context(
            sk: &SecretKey,
            prehash_oid: &[u8],
            prehash: &[u8],
            ctx: &[u8],
            seed: &[u8],
        ) -> Result<Signature, Error> {
            let rnd: [u8; 32] = seed.try_into().map_err(|_| Error::InvalidSeedLength)?;
            let prefix = $crate::sign::domain_prefix(ctx, Some((prehash_oid, prehash)))?;
            let sig = $crate::sign::sign::<$params>(sk.as_ref(), &[], &prefix, &rnd)?;
            Ok(Signature { sig })
        }

        #[doc = concat!("Sign a message with HashML-DSA-SHAKE-256 using ", $doc_variant, ".")]
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

        #[doc = concat!("Verify a ", $doc_variant, " signature.")]
        #[must_use]
        pub fn verify(pk: &PublicKey, msg: &[u8], signature: &Signature) -> bool {
            $crate::sign::verify::<$params>(&pk.pk, msg, &signature.sig)
        }

        #[doc = concat!("Verify a ", $doc_variant, " signature and return a validation error on malformed raw input.")]
        pub fn verify_result(pk: &PublicKey, msg: &[u8], signature: &Signature) -> Result<(), Error> {
            if pk.pk.len() != <$params as Params>::PUBLIC_KEY_BYTES {
                return Err(Error::InvalidKeyLength);
            }
            if signature.sig.len() != <$params as Params>::SIGNATURE_BYTES {
                return Err(Error::InvalidSignatureLength);
            }
            if $crate::sign::verify::<$params>(&pk.pk, msg, &signature.sig) {
                Ok(())
            } else {
                Err(Error::InvalidSignature)
            }
        }

        #[doc = concat!("Verify a ", $doc_variant, " pure-mode signature.")]
        #[must_use]
        pub fn verify_pure(pk: &PublicKey, msg: &[u8], signature: &Signature) -> bool {
            verify(pk, msg, signature)
        }

        #[doc = concat!("Verify a ", $doc_variant, " signature with a FIPS 204 context.")]
        #[must_use]
        pub fn verify_with_context(
            pk: &PublicKey,
            msg: &[u8],
            signature: &Signature,
            ctx: &[u8],
        ) -> bool {
            let Ok(prefix) = $crate::sign::domain_prefix(ctx, None) else {
                return false;
            };
            $crate::sign::verify_with_prefix::<$params>(&pk.pk, msg, &prefix, &signature.sig)
        }

        #[doc = concat!("Verify a prehashed ", $doc_variant, " signature with a FIPS 204 context and OID.")]
        #[must_use]
        pub fn verify_prehashed_with_context(
            pk: &PublicKey,
            prehash_oid: &[u8],
            prehash: &[u8],
            signature: &Signature,
            ctx: &[u8],
        ) -> bool {
            let Ok(prefix) = $crate::sign::domain_prefix(ctx, Some((prehash_oid, prehash))) else {
                return false;
            };
            $crate::sign::verify_with_prefix::<$params>(&pk.pk, &[], &prefix, &signature.sig)
        }

        #[doc = concat!("Verify a HashML-DSA-SHAKE-256 signature using ", $doc_variant, ".")]
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
                let (pk1, _) =
                    keygen(b"seed1234567890123456789012345678").unwrap();
                let (pk2, _) =
                    keygen(b"SEED1234567890123456789012345678").unwrap();
                assert_ne!(pk1.pk, pk2.pk);
            }

            #[test]
            fn test_sign_verify_roundtrip() {
                let seed = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
                let (pk, sk) = keygen(seed).unwrap();
                let msg = b"post-quantum ready";
                let sig = sign_deterministic(&sk, msg, &[0u8; 32]).unwrap();
                assert!(verify(&pk, msg, &sig));
            }

            #[test]
            fn test_verify_wrong_message() {
                let seed = b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
                let (pk, sk) = keygen(seed).unwrap();
                let sig = sign_deterministic(&sk, b"original message", &[0u8; 32]).unwrap();
                assert!(!verify(&pk, b"wrong message", &sig));
            }

            #[test]
            fn test_verify_wrong_key() {
                let seed_a = b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
                let seed_b = b"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
                let (pk_a, _) = keygen(seed_a).unwrap();
                let (_, sk_b) = keygen(seed_b).unwrap();
                let sig = sign_deterministic(&sk_b, b"msg", &[0u8; 32]).unwrap();
                assert!(!verify(&pk_a, b"msg", &sig));
            }
        }
    };
}
