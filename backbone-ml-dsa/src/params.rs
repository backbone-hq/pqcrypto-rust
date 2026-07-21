//! ML-DSA (FIPS 204) parameter definitions.

use crate::field::Q;

/// ML-DSA parameter set (FIPS 204).
pub trait Params {
    /// Number of polynomials in the public key matrix (rows).
    const K: usize;
    /// Number of polynomials in the secret key (columns).
    const L: usize;
    /// Error distribution parameter.
    const ETA: usize;
    /// Challenge polynomial Hamming weight.
    const TAU: usize;
    /// Beta = tau * eta, hint vector bound.
    const BETA: usize;
    /// Gamma1 parameter for high-bit encoding.
    const GAMMA1: usize;
    /// Gamma2 parameter for high/low-bit decomposition.
    const GAMMA2: usize;
    /// Number of dropped bits from t0.
    const D: usize;
    /// Maximum number of non-zero hint bits.
    const OMEGA: usize;
    /// Number of bits per coefficient in w1 encoding.
    const W1_BITS: usize;
    /// Public key size in bytes.
    const PUBLIC_KEY_BYTES: usize;
    /// Secret key size in bytes.
    const SECRET_KEY_BYTES: usize;
    /// Signature size in bytes.
    const SIGNATURE_BYTES: usize;
}

const Q32: usize = Q as usize;

#[derive(Copy, Clone, Debug)]
/// ML-DSA-44 parameter set (NIST Security Level 2).
pub struct Mldsa44;
impl Params for Mldsa44 {
    const K: usize = 4;
    const L: usize = 4;
    const ETA: usize = 2;
    const TAU: usize = 39;
    const BETA: usize = 78;
    const GAMMA1: usize = 1 << 17;
    const GAMMA2: usize = (Q32 - 1) / 88;
    const D: usize = 13;
    const OMEGA: usize = 80;
    const W1_BITS: usize = 6;
    const PUBLIC_KEY_BYTES: usize = 1312;
    const SECRET_KEY_BYTES: usize = 2560;
    const SIGNATURE_BYTES: usize = 2420;
}

#[derive(Copy, Clone, Debug)]
/// ML-DSA-65 parameter set (NIST Security Level 3).
pub struct Mldsa65;
impl Params for Mldsa65 {
    const K: usize = 6;
    const L: usize = 5;
    const ETA: usize = 4;
    const TAU: usize = 49;
    const BETA: usize = 196;
    const GAMMA1: usize = 1 << 19;
    const GAMMA2: usize = (Q32 - 1) / 32;
    const D: usize = 13;
    const OMEGA: usize = 55;
    const W1_BITS: usize = 4;
    const PUBLIC_KEY_BYTES: usize = 1952;
    const SECRET_KEY_BYTES: usize = 4032;
    const SIGNATURE_BYTES: usize = 3293;
}

#[derive(Copy, Clone, Debug)]
/// ML-DSA-87 parameter set (NIST Security Level 5).
pub struct Mldsa87;
impl Params for Mldsa87 {
    const K: usize = 8;
    const L: usize = 7;
    const ETA: usize = 2;
    const TAU: usize = 60;
    const BETA: usize = 120;
    const GAMMA1: usize = 1 << 19;
    const GAMMA2: usize = (Q32 - 1) / 32;
    const D: usize = 13;
    const OMEGA: usize = 75;
    const W1_BITS: usize = 4;
    const PUBLIC_KEY_BYTES: usize = 2592;
    const SECRET_KEY_BYTES: usize = 4896;
    const SIGNATURE_BYTES: usize = 4595;
}
