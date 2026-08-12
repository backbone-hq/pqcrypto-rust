use crate::field::Q;

/// ML-DSA parameter set: compile-time constants defining a variant.
pub trait Params {
    /// Number of rows of the module lattice matrix A.
    const K: usize;
    /// Number of columns of the module lattice matrix A.
    const L: usize;
    /// Maximum absolute value of a coefficient of the secret vectors s1, s2.
    const ETA: usize;
    /// Number of ±1 coefficients in the challenge polynomial c.
    const TAU: usize;
    /// TAU · ETA, the bound on (s1, s2)·c used in verification.
    const BETA: usize;
    /// Rejection bound on the masking vector y coefficients.
    const GAMMA1: usize;
    /// Bound on the low-order bits r0/w0 kept after rounding.
    const GAMMA2: usize;
    /// Decompose step size `ALPHA = 2 * GAMMA2` (a compile-time constant so
    /// `r / ALPHA` in `Poly::decompose` strength-reduces to multiply+shift).
    const ALPHA: usize;
    /// Security parameter in bytes (32, 48, or 64).
    const LAMBDA: usize;
    /// Number of dropped bits when splitting r into r0 ∥ r1.
    const D: usize;
    /// Maximum number of 1s in the hint vector h.
    const OMEGA: usize;
    /// Bit-width of each w1 coefficient.
    const W1_BITS: usize;
    /// Public key size in bytes (final FIPS 204).
    const PK_BYTES: usize;
    /// Secret key size in bytes (final FIPS 204).
    const SK_BYTES: usize;
    /// Signature size in bytes (final FIPS 204).
    const SIG_BYTES: usize;
}

const Q32: usize = Q as usize;

/// ML-DSA-44 parameter set (NIST security category 2).
#[derive(Copy, Clone, Debug)]
pub struct Mldsa44;
impl Params for Mldsa44 {
    const K: usize = 4;
    const L: usize = 4;
    const ETA: usize = 2;
    const TAU: usize = 39;
    const BETA: usize = 78;
    const GAMMA1: usize = 1 << 17;
    const GAMMA2: usize = (Q32 - 1) / 88;
    const ALPHA: usize = 2 * Self::GAMMA2;
    const LAMBDA: usize = 32;
    const D: usize = 13;
    const OMEGA: usize = 80;
    const W1_BITS: usize = 6;
    const PK_BYTES: usize = 1312;
    const SK_BYTES: usize = 2560;
    const SIG_BYTES: usize = 2420;
}

/// ML-DSA-65 parameter set (NIST security category 3).
#[derive(Copy, Clone, Debug)]
pub struct Mldsa65;
impl Params for Mldsa65 {
    const K: usize = 6;
    const L: usize = 5;
    const ETA: usize = 4;
    const TAU: usize = 49;
    const BETA: usize = 196;
    const GAMMA1: usize = 1 << 19;
    const GAMMA2: usize = (Q32 - 1) / 32;
    const ALPHA: usize = 2 * Self::GAMMA2;
    const LAMBDA: usize = 48;
    const D: usize = 13;
    const OMEGA: usize = 55;
    const W1_BITS: usize = 4;
    const PK_BYTES: usize = 1952;
    const SK_BYTES: usize = 4032;
    const SIG_BYTES: usize = 3309;
}

/// ML-DSA-87 parameter set (NIST security category 5).
#[derive(Copy, Clone, Debug)]
pub struct Mldsa87;
impl Params for Mldsa87 {
    const K: usize = 8;
    const L: usize = 7;
    const ETA: usize = 2;
    const TAU: usize = 60;
    const BETA: usize = 120;
    const GAMMA1: usize = 1 << 19;
    const GAMMA2: usize = (Q32 - 1) / 32;
    const ALPHA: usize = 2 * Self::GAMMA2;
    const LAMBDA: usize = 64;
    const D: usize = 13;
    const OMEGA: usize = 75;
    const W1_BITS: usize = 4;
    const PK_BYTES: usize = 2592;
    const SK_BYTES: usize = 4896;
    const SIG_BYTES: usize = 4627;
}
