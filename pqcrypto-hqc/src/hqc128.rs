//! HQC-1 (FIPS 209, security category 1).
//!
//! Provides [`keygen`], [`encaps`], [`decaps`], [`PublicKey`], and [`SecretKey`].

crate::define_variant!(Hqc128, 32, "HQC-1", "1");
