//! ML-KEM-768 (FIPS 203, security category 3).
//!
//! Provides [`keygen`], [`encaps`], [`decaps`], [`PublicKey`], and [`SecretKey`].

crate::define_variant!(MLKEM768, 32, "ML-KEM-768", "3");
