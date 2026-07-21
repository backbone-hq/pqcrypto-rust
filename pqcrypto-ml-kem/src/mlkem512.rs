//! ML-KEM-512 (FIPS 203, security category 1).
//!
//! Provides [`keygen`], [`encaps`], [`decaps`], [`PublicKey`], and [`SecretKey`].

crate::define_variant!(MLKEM512, 32, "ML-KEM-512", "1");
