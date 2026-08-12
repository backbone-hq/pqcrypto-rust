/// Define a typed KEM variant module for Classic McEliece.
///
/// Generates `PublicKey`, `SecretKey`, and `Encapsulation` structs
/// along with `keygen`, `keygen_with_rng`, `encaps`, `encaps_with_rng`,
/// and `decaps` functions that delegate to the shared `$core` module.
///
/// # Parameters
/// - `$params`: marker struct name (e.g., `McEliece348864`)
/// - `$core`: shared module crate path (e.g., `gf12` or `gf13`)
/// - `$doc_variant`: doc string for the variant
///
/// Optional FFT table names (default: `FFT_CONSTS`, `FFT_POWERS`, `FFT_SCALARS`):
/// - `fft_consts = $c`, `fft_powers = $p`, `fft_scalars = $s` (per-variant names)
/// - GF13 variants additionally pass `fft_extra = FFT_POWERS` (4 tables vs 3)
///
/// # Required items in scope
/// - `$core` module must export: `syndrome_from_public_key`, `decrypt_error_vector`,
///   `pk_gen`, `genpoly_gen`, `controlbits_from_permutation`, `load_gf`, `store_gf`,
///   `load4`, `store8`, `shake256_into`, all constants (GFBITS, SYS_N, SYS_T, etc.)
#[macro_export]
macro_rules! define_variant {
    ($params:ident, $core:ident, $doc_variant:expr) => {
        $crate::define_variant!($params, $core, $doc_variant,
            fft_consts = FFT_CONSTS, fft_powers = FFT_POWERS, fft_scalars = FFT_SCALARS);
    };
    ($params:ident, $core:ident, $doc_variant:expr,
     fft_consts = $consts:ident, fft_powers = $powers:ident, fft_scalars = $scalars:ident) => {
        $crate::define_variant!(@body $params, $core, $doc_variant,
            $consts, $powers, $scalars, false);
    };
    ($params:ident, $core:ident, $doc_variant:expr,
     fft_consts = $consts:ident, fft_powers = $powers:ident, fft_scalars = $scalars:ident,
     fast = true) => {
        $crate::define_variant!(@body $params, $core, $doc_variant,
            $consts, $powers, $scalars, true);
    };
    ($params:ident, $core:ident, $doc_variant:expr,
     fft_consts = $consts:ident, fft_powers = $powers:ident, fft_scalars = $scalars:ident,
     fft_extra = $extra:ident) => {
        $crate::define_variant!(@body $params, $core, $doc_variant,
            $consts, $powers, $scalars, false, $extra);
    };
    ($params:ident, $core:ident, $doc_variant:expr,
     fft_consts = $consts:ident, fft_powers = $powers:ident, fft_scalars = $scalars:ident,
     fft_extra = $extra:ident, fast = true) => {
        $crate::define_variant!(@body $params, $core, $doc_variant,
            $consts, $powers, $scalars, true, $extra);
    };
    (@body $params:ident, $core:ident, $doc_variant:expr,
     $consts:ident, $powers:ident, $scalars:ident, $fast:tt $(, $extra:ident)?) => {
        use alloc::vec::Vec;
        use backbone_pqcrypto_internals::nist_seed_expander::NistSeedExpander;
        use backbone_pqcrypto_internals::secret::{SecretArray, SecretVec};
        use $crate::error::Error;
        use $crate::rand_core::CryptoRngCore;

                use zeroize::Zeroize;

        const CRYPTO_PUBLICKEYBYTES: usize = $core::CRYPTO_PUBLICKEYBYTES;
        const CRYPTO_SECRETKEYBYTES: usize = $core::CRYPTO_SECRETKEYBYTES;
        const CRYPTO_CIPHERTEXTBYTES: usize = $core::CRYPTO_CIPHERTEXTBYTES;
        const CRYPTO_BYTES: usize = $core::CRYPTO_BYTES;

        const GFBITS: usize = $core::GFBITS;
        const SYS_T: usize = $core::SYS_T;
        const SYS_N: usize = $core::SYS_N;
        const COND_BYTES: usize = $core::COND_BYTES;
        const IRR_BYTES: usize = $core::IRR_BYTES;
        const SYND_BYTES: usize = $core::SYND_BYTES;
        const GFMASK: u16 = $core::GFMASK;

        /// Classic McEliece public key.
        #[doc = concat!($doc_variant, " public key.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct PublicKey {
            #[doc = concat!("Raw ", $doc_variant, " public key bytes.")]
            pub pk: Vec<u8>,
        }

        /// Classic McEliece secret key.
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
            /// Shared secret (32 bytes).
            pub shared_secret: [u8; CRYPTO_BYTES],
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


        fn gen_e_from_drbg(drbg: &mut NistSeedExpander) -> [u8; SYS_N / 8] {
            let direct = SYS_N == (1 << GFBITS);
            loop {
                let bytes_needed = if direct { SYS_T * 2 } else { SYS_T * 2 * 2 };
                let mut buf = SecretVec::<u8>::new(bytes_needed);
                drbg.fill_bytes(buf.as_mut());

                let mut positions = [0u16; SYS_T];
                let mut count = 0usize;
                for chunk in buf.chunks_exact(2) {
                    if count >= SYS_T {
                        break;
                    }
                    let candidate = $core::load_gf(chunk) & GFMASK;
                    if direct || (candidate as usize) < SYS_N {
                        positions[count] = candidate;
                        count += 1;
                    }
                }
                if count < SYS_T {
                    continue;
                }

                let mut has_dup = false;
                'outer: for i in 1..SYS_T {
                    for j in 0..i {
                        if positions[i] == positions[j] {
                            has_dup = true;
                            break 'outer;
                        }
                    }
                }
                if has_dup {
                    continue;
                }

                let mut e = [0u8; SYS_N / 8];
                for &pos in &positions {
                    let idx = pos as usize;
                    e[idx / 8] |= 1 << (idx % 8);
                }
                return e;
            }
        }


        /// SHAKE256 hash producing a 32-byte output.
        fn shake256_32(input: &[u8]) -> [u8; 32] {
            let mut out = [0u8; 32];
            $core::shake256_into(&mut out, input);
            out
        }

        #[must_use]
        fn encaps_from_drbg(pk: &[u8], drbg: &mut NistSeedExpander) -> Encapsulation {
            let e = gen_e_from_drbg(drbg);
            let ciphertext = $core::syndrome_from_public_key(pk, &e).to_vec();
            // Zeroizing preimage: it contains the secret error vector e.
            let mut preimage = SecretVec::<u8>::new(1 + SYS_N / 8 + SYND_BYTES);
            preimage[0] = 1;
            preimage[1..1 + SYS_N / 8].copy_from_slice(&e);
            preimage[1 + SYS_N / 8..].copy_from_slice(&ciphertext);
            let shared_secret = shake256_32(preimage.as_ref());
            Encapsulation {
                ciphertext,
                shared_secret,
            }
        }

        fn decaps_bytes(sk: &[u8], ciphertext: &[u8]) -> Result<[u8; CRYPTO_BYTES], Error> {
            if sk.len() != CRYPTO_SECRETKEYBYTES {
                return Err(Error::InvalidSecretKeyLength);
            }
            if ciphertext.len() != CRYPTO_CIPHERTEXTBYTES {
                return Err(Error::InvalidCiphertextLength);
            }

            let fallback_s =
                &sk[40 + IRR_BYTES + COND_BYTES..40 + IRR_BYTES + COND_BYTES + SYS_N / 8];
            let (e_arr, valid) = $core::decrypt_error_vector(sk, ciphertext);
            let e = SecretArray::from_array(e_arr);

            let valid_choice = subtle::Choice::from(valid & 1);
            let mut chosen = [0u8; SYS_N / 8];
            for i in 0..SYS_N / 8 {
                chosen[i] = <u8 as subtle::ConditionallySelectable>::conditional_select(
                    &fallback_s[i],
                    &e[i],
                    valid_choice,
                );
            }

            let prefix = valid & 1;
            // Zeroizing preimage: it contains the secret error vector (chosen).
            let mut preimage = SecretVec::<u8>::new(1 + SYS_N / 8 + SYND_BYTES);
            preimage[0] = prefix;
            preimage[1..1 + SYS_N / 8].copy_from_slice(&chosen);
            preimage[1 + SYS_N / 8..].copy_from_slice(ciphertext);
            let shared = shake256_32(preimage.as_ref());

            Ok(shared)
        }


        fn keypair_from_seed_bytes(seed32: [u8; 32]) -> Result<(PublicKey, SecretKey), Error> {
            let mut seed = SecretArray::<u8, 33>::new();
            seed[0] = 64;
            seed.as_mut()[1..33].copy_from_slice(&seed32);

            let expand_len = SYS_N / 8 + (1 << GFBITS) * 4 + SYS_T * 2 + 32;
            let mut r = SecretVec::<u8>::new(expand_len);

            for _attempt in 0..1024 {
                $core::shake256_into(&mut r, seed.as_ref());

                let mut secret_key = zeroize::Zeroizing::new(alloc::vec![0u8; CRYPTO_SECRETKEYBYTES]);
                secret_key[..32].copy_from_slice(&seed.as_ref()[1..]);
                seed.as_mut()[1..].copy_from_slice(&r[expand_len - 32..]);

                let mut rp = expand_len - 32;

                rp -= SYS_T * 2;
                let mut f = SecretArray::<u16, SYS_T>::new();
                for i in 0..SYS_T {
                    f[i] = $core::load_gf(&r[rp + i * 2..]) & GFMASK;
                }

                let mut irr = SecretArray::<u16, SYS_T>::new();
                if $core::genpoly_gen(&mut *irr, &*f) {
                    continue;
                }

                let mut skp = 40usize;
                for &value in irr.iter() {
                    $core::store_gf(&mut secret_key[skp..], value);
                    skp += 2;
                }

                rp -= (1 << GFBITS) * 4;
                let mut perm = SecretArray::<u32, { 1 << GFBITS }>::new();
                for i in 0..(1 << GFBITS) {
                    perm[i] = u32::try_from($core::load4(&r[rp + i * 4..]))
                        .expect("load4 reads 4 bytes, max u32::MAX");
                }

                let mut pi = SecretArray::<i16, { 1 << GFBITS }>::new();

                let mut public_key = Vec::with_capacity(CRYPTO_PUBLICKEYBYTES);
                let mut pivots = 0u64;
                let pivot_arg = if $fast {
                    Some(&mut pivots)
                } else {
                    None
                };
                if $core::pk_gen(
                    &mut public_key,
                    &secret_key[40..40 + IRR_BYTES],
                    &*perm,
                    &mut *pi,
                    &$consts,
                    &$powers,
                    &$scalars,
                    $(
                        &$extra,
                    )*
                    pivot_arg,
                )
                .is_err()
                {
                    continue;
                }

                let cond_start = 40 + IRR_BYTES;
                $core::controlbits_from_permutation(
                    &mut secret_key[cond_start..cond_start + COND_BYTES],
                    &*pi,
                )?;

                rp -= SYS_N / 8;
                let sk_ev_end = cond_start + COND_BYTES + SYS_N / 8;
                secret_key[cond_start + COND_BYTES..sk_ev_end]
                    .copy_from_slice(&r[rp..rp + SYS_N / 8]);

                if $fast {
                    $core::store8(&mut secret_key[32..40], pivots);
                } else {
                    $core::store8(&mut secret_key[32..40], 0xFFFF_FFFF);
                }

                return Ok((PublicKey { pk: public_key }, SecretKey {
                    sk: core::mem::take(secret_key.as_mut()),
                }));
            }

            Err(Error::KeygenFailed)
        }


        /// Key-generation seed length in bytes — the single source of truth for
        /// both `keygen()` (system randomness) and `keygen_with_rng()` (caller RNG).
        const KEYGEN_SEED_LEN: usize = 48;

        #[doc = concat!("Generate an ", $doc_variant, " keypair using system randomness.")]
        pub fn keygen() -> Result<(PublicKey, SecretKey), Error> {
            let mut seed = SecretArray::<u8, KEYGEN_SEED_LEN>::new();
            getrandom::getrandom(seed.as_mut()).map_err(|_| Error::RngFailure)?;
            keygen_from_seed(&seed)
        }

        #[doc = concat!("Generate an ", $doc_variant, " keypair using a caller-provided RNG.")]
        #[doc = "Draws exactly `KEYGEN_SEED_LEN` bytes from `rng` and expands them via the "]
        #[doc = "NIST AES-256-CTR DRBG, matching the official KAT harness."]
        pub fn keygen_with_rng(
            rng: &mut impl CryptoRngCore,
        ) -> Result<(PublicKey, SecretKey), Error> {
            let mut seed = SecretArray::<u8, KEYGEN_SEED_LEN>::new();
            rng.try_fill_bytes(seed.as_mut()).map_err(|_| Error::RngFailure)?;
            keygen_from_seed(&seed)
        }

        fn keygen_from_seed(seed: &[u8; KEYGEN_SEED_LEN]) -> Result<(PublicKey, SecretKey), Error> {
            let mut drbg = NistSeedExpander::new(seed);
            let mut seed32 = SecretArray::<u8, 32>::new();
            drbg.fill_bytes(seed32.as_mut());
            keypair_from_seed_bytes(*seed32)
        }


        #[doc = concat!("Encapsulate a shared secret under an ", $doc_variant, " public key.")]
        pub fn encaps(pk: &PublicKey) -> Result<Encapsulation, Error> {
            if pk.pk.len() != CRYPTO_PUBLICKEYBYTES {
                return Err(Error::InvalidKeyLength);
            }
            let mut seed = [0u8; 48];
            getrandom::getrandom(&mut seed).map_err(|_| Error::RngFailure)?;
            encaps_from_seed(&pk.pk, &seed)
        }

        #[doc = concat!("Encapsulate a shared secret under an ", $doc_variant, " public key ")]
        #[doc = "using a caller-provided RNG."]
        #[doc = "Draws exactly 48 bytes from `rng` and expands them via the NIST "]
        #[doc = "AES-256-CTR DRBG, matching the official KAT harness."]
        pub fn encaps_with_rng(
            pk: &PublicKey,
            rng: &mut impl CryptoRngCore,
        ) -> Result<Encapsulation, Error> {
            if pk.pk.len() != CRYPTO_PUBLICKEYBYTES {
                return Err(Error::InvalidKeyLength);
            }
            let mut seed = [0u8; 48];
            rng.try_fill_bytes(&mut seed).map_err(|_| Error::RngFailure)?;
            encaps_from_seed(&pk.pk, &seed)
        }

        fn encaps_from_seed(pk_bytes: &[u8], seed: &[u8; 48]) -> Result<Encapsulation, Error> {
            let mut drbg = NistSeedExpander::new(seed);
            let mut skip = [0u8; 32];
            drbg.fill_bytes(&mut skip);
            Ok(encaps_from_drbg(pk_bytes, &mut drbg))
        }

        #[doc = concat!("Decapsulate a shared secret from a ciphertext using an ", $doc_variant, " secret key.")]
        pub fn decaps(
            sk: &SecretKey,
            ciphertext: &[u8],
        ) -> Result<[u8; CRYPTO_BYTES], Error> {
            decaps_bytes(sk.as_ref(), ciphertext)
        }

        impl AsRef<[u8]> for PublicKey {
            fn as_ref(&self) -> &[u8] {
                &self.pk
            }
        }

        impl PublicKey {
            /// Construct from raw bytes.
            #[doc = concat!("Construct an ", $doc_variant, " public key from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != CRYPTO_PUBLICKEYBYTES {
                    return Err(Error::InvalidKeyLength);
                }
                Ok(Self { pk: bytes.to_vec() })
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
                if bytes.len() != CRYPTO_SECRETKEYBYTES {
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
            use alloc::vec;
            use backbone_pqcrypto_internals::kat::FixedRng;

            #[test]
            fn test_keygen_with_rng() {
                let seed = vec![0x42u8; 48];
                let (pk1, _) = keygen_with_rng(&mut FixedRng::new(seed.clone())).expect("keygen 1");
                let (pk2, _) = keygen_with_rng(&mut FixedRng::new(seed)).expect("keygen 2");
                let enc1 = encaps(&pk1).expect("encaps 1");
                let enc2 = encaps(&pk2).expect("encaps 2");
                assert_eq!(enc1.ciphertext.len(), enc2.ciphertext.len());
            }

            #[test]
            fn test_keygen_different_seeds() {
                let (pk1, _) =
                    keygen_with_rng(&mut FixedRng::new(vec![0x00u8; 48])).expect("keygen 1");
                let (pk2, _) =
                    keygen_with_rng(&mut FixedRng::new(vec![0x01u8; 48])).expect("keygen 2");
                assert_ne!(pk1.pk, pk2.pk, "different seeds should produce different keys");
            }

            #[test]
            fn test_keygen_roundtrip() {
                let (pk, sk) = keygen_with_rng(&mut FixedRng::new(vec![0x42u8; 48])).expect("keygen");
                assert_eq!(pk.as_ref().len(), CRYPTO_PUBLICKEYBYTES);
                assert_eq!(sk.as_ref().len(), CRYPTO_SECRETKEYBYTES);
            }

            #[test]
            fn test_encaps_decaps_roundtrip() {
                let (pk, sk) =
                    keygen_with_rng(&mut FixedRng::new(vec![255u8; 48])).expect("keygen");
                let enc =
                    encaps_with_rng(&pk, &mut FixedRng::new(vec![255u8; 48])).expect("encaps");
                let ss = decaps(&sk, &enc.ciphertext).expect("decaps");
                assert_eq!(enc.shared_secret, ss, "shared secrets must match");
            }

            #[test]
            fn test_encaps_with_rng() {
                let (pk, _) = keygen_with_rng(&mut FixedRng::new(vec![0x42u8; 48])).expect("keygen");
                let enc1 =
                    encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48])).expect("encaps 1");
                let enc2 =
                    encaps_with_rng(&pk, &mut FixedRng::new(vec![0x13u8; 48])).expect("encaps 2");
                assert_eq!(enc1.ciphertext, enc2.ciphertext, "deterministic ciphertexts");
                assert_eq!(
                    enc1.shared_secret,
                    enc2.shared_secret,
                    "deterministic shared secrets"
                );
            }

            #[test]
            fn test_wrong_key_decaps_fails() {
                let (pk1, _) =
                    keygen_with_rng(&mut FixedRng::new(vec![0x42u8; 48])).expect("keygen 1");
                let (_, sk2) =
                    keygen_with_rng(&mut FixedRng::new(vec![0x99u8; 48])).expect("keygen 2");
                let enc =
                    encaps_with_rng(&pk1, &mut FixedRng::new(vec![0x13u8; 48])).expect("encaps");
                let ss = decaps(&sk2, &enc.ciphertext).expect("decaps with wrong key");
                assert_ne!(
                    enc.shared_secret,
                    ss,
                    "wrong key should produce different shared secret"
                );
            }

            #[test]
            fn test_invalid_ciphertext_rejected() {
                let (_, sk) =
                    keygen_with_rng(&mut FixedRng::new(vec![0x42u8; 48])).expect("keygen");
                let result = decaps(&sk, &[0u8; 1]);
                assert!(result.is_err(), "short ciphertext should be rejected");
                let bad_ct = vec![0u8; CRYPTO_CIPHERTEXTBYTES + 1];
                let result = decaps(&sk, &bad_ct);
                assert!(result.is_err(), "wrong-length ciphertext should be rejected");
            }

            #[test]
            fn test_generated_ct_rejected() {
                let (_, sk) =
                    keygen_with_rng(&mut FixedRng::new(vec![0x42u8; 48])).expect("keygen");
                let random_ct = [0xABu8; CRYPTO_CIPHERTEXTBYTES];
                let result = decaps(&sk, &random_ct);
                assert!(result.is_ok(), "random-ciphertext decaps must not panic");
            }
        }
    };
}
