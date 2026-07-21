//! HQC-3 (FIPS 209, security category 3).
//!
//! Provides [`keygen`], [`encaps`], [`decaps`], [`PublicKey`], and [`SecretKey`].

crate::define_variant!(Hqc192, 32, "HQC-3", "3");
