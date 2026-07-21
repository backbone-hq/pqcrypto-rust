//! ML-KEM-1024 (FIPS 203, security category 5).
//!
//! Provides [`keygen`], [`encaps`], [`decaps`], [`PublicKey`], and [`SecretKey`].

crate::define_variant!(MLKEM1024, 32, "ML-KEM-1024", "5");
