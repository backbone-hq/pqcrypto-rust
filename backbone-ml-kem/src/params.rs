//! ML-KEM parameter set definitions following FIPS 203.

/// ML-KEM parameter set definitions following FIPS 203.
pub trait Params {
    /// Module rank
    const K: usize;
    /// Eta for the first CBD distribution
    const ETA1: usize;
    /// Eta for the second CBD distribution
    const ETA2: usize;
    /// Bit-length of compressed u component
    const DU: usize;
    /// Bit-length of compressed v component
    const DV: usize;
    /// Public key size in bytes
    const PK_SIZE: usize;
    /// Ciphertext size in bytes
    const CT_SIZE: usize;
}

/// ML-KEM-512 (security category 1) parameter set.
#[derive(Copy, Clone, Debug)]
pub struct MLKEM512;
impl Params for MLKEM512 {
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
    const PK_SIZE: usize = 800;
    const CT_SIZE: usize = 768;
}

/// ML-KEM-768 (security category 3) parameter set.
#[derive(Copy, Clone, Debug)]
pub struct MLKEM768;
impl Params for MLKEM768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
    const PK_SIZE: usize = 1184;
    const CT_SIZE: usize = 1088;
}

/// ML-KEM-1024 (security category 5) parameter set.
#[derive(Copy, Clone, Debug)]
pub struct MLKEM1024;
impl Params for MLKEM1024 {
    const K: usize = 4;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
    const PK_SIZE: usize = 1568;
    const CT_SIZE: usize = 1568;
}

/// Polynomial degree (N = 256 per FIPS 203).
pub const N: usize = 256;
pub(crate) const Q: i32 = 3329;
/// Byte length of a serialized polynomial (256 * 12 / 8).
pub const POLY_BYTES: usize = 384;
