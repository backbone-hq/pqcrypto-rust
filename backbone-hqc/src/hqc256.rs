//! HQC-5 (FIPS 209, security category 5).
//!
//! Provides [`keygen`], [`encaps`], [`decaps`], [`PublicKey`], and [`SecretKey`].

crate::define_variant!(Hqc256, 32, "HQC-5", "5");
