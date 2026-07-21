/// Define a typed KEM variant module for Classic McEliece.
///
/// Generates `PublicKey`, `SecretKey`, and `Encapsulation` structs
/// along with `keygen`, `keypair_from_seed`, `encaps`, `encaps_deterministic`,
/// and `decaps` functions that delegate to the shared `$core` module.
///
/// # Parameters
/// - `$params`: marker struct name (e.g., `McEliece348864`)
/// - `$core`: shared module crate path (e.g., `gf12` or `gf13`)
/// - `$doc_variant`: doc string for the variant
/// - `$doc_sec`: security level string
///
/// Optional FFT table names (default: `FFT_CONSTS`, `FFT_POWERS`, `FFT_SCALARS`):
/// - `fft_consts = $c`: name of the FFT_CONSTS table (e.g., `FFT_CONSTS`)
/// - `fft_powers = $p`: name of the FFT_POWERS table
/// - `fft_scalars = $s`: name of the FFT_SCALARS table
///
/// For GF13 variants, pass GF13-specific FFT table names:
/// `define_variant!(..., fft_consts = FFT_CONSTS, fft_powers = FFT_SCALARS_2X, fft_scalars = FFT_SCALARS_4X,
///     fft_extra = FFT_POWERS)`
/// (GF12 provides 3 FFT tables; GF13 provides 4 — consts, scalars_2x, scalars_4x, powers;
///  `$core::pk_gen` resolves the correct types and count).
///
/// # Required items in scope
/// - FFT table constants (from the `include!()`)
/// - `$core` module must export: `syndrome_from_public_key`, `decrypt_error_vector`,
///   `pk_gen`, `genpoly_gen`, `controlbits_from_permutation`, `load_gf`, `store_gf`,
///   `load4`, `store8`, `shake256_into`, all constants (GFBITS, SYS_N, SYS_T, etc.)
#[macro_export]
macro_rules! define_variant {
    // GF12-style: default FFT table names (3 tables)
    ($params:ident, $core:ident, $doc_variant:expr, $doc_sec:expr) => {
        $crate::define_variant!($params, $core, $doc_variant, $doc_sec,
            fft_consts = FFT_CONSTS, fft_powers = FFT_POWERS, fft_scalars = FFT_SCALARS);
    };
    // 3-table form (GF12-style)
    ($params:ident, $core:ident, $doc_variant:expr, $doc_sec:expr,
     fft_consts = $consts:ident, fft_powers = $powers:ident, fft_scalars = $scalars:ident) => {
        $crate::define_variant!(@body $params, $core, $doc_variant, $doc_sec,
            $consts, $powers, $scalars);
    };
    // 4-table form (GF13+)
    ($params:ident, $core:ident, $doc_variant:expr, $doc_sec:expr,
     fft_consts = $consts:ident, fft_powers = $powers:ident, fft_scalars = $scalars:ident,
     fft_extra = $extra:ident) => {
        $crate::define_variant!(@body $params, $core, $doc_variant, $doc_sec,
            $consts, $powers, $scalars, $extra);
    };
    // ── Internal body (shared by both 3-table and 4-table forms) ─────
    (@body $params:ident, $core:ident, $doc_variant:expr, $doc_sec:expr,
     $consts:ident, $powers:ident, $scalars:ident $(, $extra:ident)?) => {
        use alloc::vec::Vec;
        use pqcrypto_utils::secret::{SecretArray, SecretVec};
        #[cfg(feature = "zeroize")]
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
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct PublicKey {
            /// The raw public key bytes.
            pub pk: Vec<u8>,
        }

        /// Classic McEliece secret key.
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
            pub shared_secret: [u8; 32],
            /// The ciphertext.
            pub ciphertext: Vec<u8>,
        }

        // ── Error-vector generation ──────────────────────────────────────

        /// Generate an error vector of weight `SYS_T` from a 32-byte seed.
        fn gen_e_from_seed(seed32: [u8; 32]) -> [u8; SYS_N / 8] {
            let mut buf = [0u8; SYS_T * 2 * 2];
            let mut domain = [0u8; 40];
            domain[..32].copy_from_slice(&seed32);
            let mut counter = 0u64;

            loop {
                domain[32..40].copy_from_slice(&counter.to_le_bytes());
                counter = counter.wrapping_add(1);
                $core::shake256_into(&mut buf, &domain);

                let mut positions = [0u16; SYS_T];
                let mut count = 0usize;
                for chunk in buf.chunks_exact(2) {
                    if count >= SYS_T {
                        break;
                    }
                    let candidate = $core::load_gf(chunk) & GFMASK;
                    if (candidate as usize) < SYS_N {
                        positions[count] = candidate;
                        count += 1;
                    }
                }
                if count < SYS_T {
                    continue;
                }

                // Check for duplicates
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

                // Convert to error bytes
                let mut e = [0u8; SYS_N / 8];
                for &pos in &positions {
                    let idx = pos as usize;
                    e[idx / 8] |= 1 << (idx % 8);
                }
                return e;
            }
        }

        // ── Encapsulation ────────────────────────────────────────────────

        /// SHAKE256 hash producing a 32-byte output.
        fn shake256_32(input: &[u8]) -> [u8; 32] {
            let mut out = [0u8; 32];
            $core::shake256_into(&mut out, input);
            out
        }

        #[must_use]
        fn encaps_from_seed_bytes(pk: &[u8], seed32: [u8; 32]) -> Encapsulation {
            let e = gen_e_from_seed(seed32);
            let ciphertext = $core::syndrome_from_public_key(pk, &e).to_vec();
            let mut preimage = Vec::with_capacity(1 + SYS_N / 8 + SYND_BYTES);
            preimage.push(1u8);
            preimage.extend_from_slice(&e);
            preimage.extend_from_slice(&ciphertext);
            let shared_secret = shake256_32(&preimage);
            Encapsulation {
                ciphertext,
                shared_secret,
            }
        }

        fn decaps_bytes(sk: &[u8], ct: &[u8]) -> Result<[u8; CRYPTO_BYTES], $crate::error::Error> {
            if sk.len() != CRYPTO_SECRETKEYBYTES {
                return Err($crate::error::Error::InvalidSecretKeyLength);
            }
            if ct.len() != CRYPTO_CIPHERTEXTBYTES {
                return Err($crate::error::Error::InvalidCiphertextLength);
            }

            let fallback_s =
                &sk[40 + IRR_BYTES + COND_BYTES..40 + IRR_BYTES + COND_BYTES + SYS_N / 8];
            let (e_arr, valid) = $core::decrypt_error_vector(sk, ct);
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
            let mut preimage = Vec::with_capacity(1 + SYS_N / 8 + SYND_BYTES);
            preimage.push(prefix);
            preimage.extend_from_slice(&chosen);
            preimage.extend_from_slice(ct);
            let shared = shake256_32(&preimage);

            Ok(shared)
        }

        // ── Key generation ──────────────────────────────────────────────

        fn keypair_from_seed_bytes(seed32: [u8; 32]) -> Result<(PublicKey, SecretKey), $crate::error::Error> {
            let mut seed = SecretArray::<u8, 33>::new();
            seed[0] = 64;
            seed.as_mut()[1..33].copy_from_slice(&seed32);

            let expand_len = SYS_N / 8 + (1 << GFBITS) * 4 + SYS_T * 2 + 32;
            let mut r = SecretVec::<u8>::new(expand_len);

            for _attempt in 0..1024 {
                $core::shake256_into(&mut r, seed.as_ref());

                let mut secret_key = alloc::vec![0u8; CRYPTO_SECRETKEYBYTES];
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

                $core::store8(&mut secret_key[32..40], 0xFFFF_FFFF_FFFF_FFFF);

                return Ok((PublicKey { pk: public_key }, SecretKey { sk: secret_key }));
            }

            Err($crate::error::Error::KeygenFailed)
        }

        // ── Public KEM API ──────────────────────────────────────────────

        /// Generate a keypair deterministically from a seed.
        ///
        /// The seed is expanded via SHAKE-256. Any seed length is accepted.
        #[doc = concat!("Generate an ", $doc_variant, " keypair deterministically from a seed.")]
        pub fn keygen(seed: &[u8]) -> Result<(PublicKey, SecretKey), $crate::error::Error> {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut shake = sha3::Shake256::default();
            Update::update(&mut shake, seed);
            let mut reader = shake.finalize_xof();
            let mut seed32 = [0u8; 32];
            reader.read(&mut seed32);
            keypair_from_seed_bytes(seed32)
        }
        /// Generate a keypair from a seed (alias for keygen).
        pub fn keypair_from_seed(seed: &[u8]) -> Result<(PublicKey, SecretKey), $crate::error::Error> {
            keygen(seed)
        }

        /// Encapsulate a shared secret under this public key.
        #[doc = concat!("Encapsulate a shared secret under an ", $doc_variant, " public key.")]
        pub fn encaps(pk: &PublicKey) -> Result<Encapsulation, $crate::error::Error> {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|_| $crate::error::Error::RngFailure)?;
            encaps_deterministic(pk, &seed)
        }

        /// Encapsulate a shared secret under this public key using a specific seed.
        #[doc = concat!("Encapsulate a shared secret under an ", $doc_variant, " public key using a specific seed.")]
        pub fn encaps_deterministic(
            pk: &PublicKey,
            seed: &[u8],
        ) -> Result<Encapsulation, $crate::error::Error> {
            if pk.pk.len() != CRYPTO_PUBLICKEYBYTES {
                return Err($crate::error::Error::InvalidKeyLength);
            }
            if seed.len() < 32 {
                return Err($crate::error::Error::InvalidKeyLength);
            }
            let seed32: &[u8; 32] = &seed[..32].try_into().expect("length checked above");
            Ok(encaps_from_seed_bytes(&pk.pk, *seed32))
        }

        /// Decapsulate a shared secret from a ciphertext using this secret key.
        #[doc = concat!("Decapsulate a shared secret from a ciphertext using an ", $doc_variant, " secret key.")]
        pub fn decaps(
            sk: &SecretKey,
            ct: &[u8],
        ) -> Result<[u8; CRYPTO_BYTES], $crate::error::Error> {
            decaps_bytes(sk.as_ref(), ct)
        }

        // AsRef impls
        impl AsRef<[u8]> for PublicKey {
            fn as_ref(&self) -> &[u8] {
                &self.pk
            }
        }

        impl PublicKey {
            /// Construct from raw bytes.
            #[doc = concat!("Construct an ", $doc_variant, " public key from raw bytes.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, $crate::error::Error> {
                if bytes.len() != CRYPTO_PUBLICKEYBYTES {
                    return Err($crate::error::Error::InvalidKeyLength);
                }
                Ok(Self { pk: bytes.to_vec() })
            }

            /// Return the raw public key bytes.
            pub fn as_bytes(&self) -> &[u8] {
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
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, $crate::error::Error> {
                if bytes.len() != CRYPTO_SECRETKEYBYTES {
                    return Err($crate::error::Error::InvalidSecretKeyLength);
                }
                Ok(Self { sk: bytes.to_vec() })
            }

            /// Return the raw secret key bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.sk
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use alloc::vec;

            #[test]
            fn test_keygen_deterministic() {
                let seed = [0x42u8; 32];
                let (pk1, _) = keygen(&seed).expect("keygen 1");
                let (pk2, _) = keygen(&seed).expect("keygen 2");
                let enc1 = encaps(&pk1).expect("encaps 1");
                let enc2 = encaps(&pk2).expect("encaps 2");
                assert_eq!(enc1.ciphertext.len(), enc2.ciphertext.len());
            }

            #[test]
            fn test_keygen_different_seeds() {
                let (pk1, _) = keygen(&[0x00u8; 32]).expect("keygen 1");
                let (pk2, _) = keygen(&[0x01u8; 32]).expect("keygen 2");
                assert_ne!(pk1.pk, pk2.pk, "different seeds should produce different keys");
            }

            #[test]
            fn test_keygen_roundtrip() {
                let (pk, sk) = keygen(&[0x42u8; 32]).expect("keygen");
                assert_eq!(pk.as_ref().len(), CRYPTO_PUBLICKEYBYTES);
                assert_eq!(sk.as_ref().len(), CRYPTO_SECRETKEYBYTES);
            }

            #[test]
            fn test_encaps_decaps_roundtrip() {
                let (pk, sk) = keygen(&[255u8; 32]).expect("keygen");
                let r_seed = [255u8; 32];
                let enc = encaps_deterministic(&pk, &r_seed).expect("encaps");
                let ss = decaps(&sk, &enc.ciphertext).expect("decaps");
                assert_eq!(enc.shared_secret, ss, "shared secrets must match");
            }

            #[test]
            fn test_encaps_deterministic() {
                let (pk, _) = keygen(&[0x42u8; 32]).expect("keygen");
                let e_seed = [0x13u8; 32];
                let enc1 = encaps_deterministic(&pk, &e_seed).expect("encaps 1");
                let enc2 = encaps_deterministic(&pk, &e_seed).expect("encaps 2");
                assert_eq!(enc1.ciphertext, enc2.ciphertext, "deterministic ciphertexts");
                assert_eq!(enc1.shared_secret, enc2.shared_secret, "deterministic shared secrets");
            }

            #[test]
            fn test_wrong_key_decaps_fails() {
                let (pk1, _) = keygen(&[0x42u8; 32]).expect("keygen 1");
                let (_, sk2) = keygen(&[0x99u8; 32]).expect("keygen 2");
                let r_seed = [0x13u8; 32];
                let enc = encaps_deterministic(&pk1, &r_seed).expect("encaps");
                let ss = decaps(&sk2, &enc.ciphertext).expect("decaps with wrong key");
                assert_ne!(enc.shared_secret, ss, "wrong key should produce different shared secret");
            }

            #[test]
            fn test_invalid_ciphertext_rejected() {
                let (_, sk) = keygen(&[0x42u8; 32]).expect("keygen");
                let result = decaps(&sk, &[0u8; 1]);
                assert!(result.is_err(), "short ciphertext should be rejected");
                let bad_ct = vec![0u8; CRYPTO_CIPHERTEXTBYTES + 1];
                let result = decaps(&sk, &bad_ct);
                assert!(result.is_err(), "wrong-length ciphertext should be rejected");
            }

            #[test]
            fn test_generated_ct_rejected() {
                let (_, sk) = keygen(&[0x42u8; 32]).expect("keygen");
                let random_ct = [0xABu8; CRYPTO_CIPHERTEXTBYTES];
                let result = decaps(&sk, &random_ct);
                assert!(result.is_ok(), "random-ciphertext decaps must not panic");
            }
        }
    };
}
