//! NTRU LPRime parameters.
//! Uses the same ring as Streamlined NTRU Prime
//! but with different weight and key/ciphertext sizes.

use crate::poly::{r3_encoded_bytes, rq_rounded_bytes};

/// NTRUPLR parameters.
pub trait Params {
    /// Ring dimension.
    const P: usize;
    /// Field modulus for Rq.
    const Q: i16;
    /// Polynomial weight (for small polynomials).
    const W: usize;
    /// Public key size: 32 (seed K) + rounded.
    const PK_BYTES: usize;
    /// Secret key size: small enc + PK + 64 (rho + cache).
    const SK_BYTES: usize;
    /// Ciphertext size: rounded(B) + 128 (packed C) + 32 (confirm).
    const CT_BYTES: usize;
    /// Shared secret size.
    const SS_BYTES: usize;
    /// Number of C coefficients (256 = 128 bytes packed).
    const C_COUNT: usize;
    /// Top/Right tau0 constant.
    const TAU0: i32;
    /// Top/Right tau1 constant.
    const TAU1: i32;
    /// Top/Right tau2 constant.
    const TAU2: i32;
    /// Top/Right tau3 constant.
    const TAU3: i32;
}

/// NTRUPLR parameter set: ntruplr761 (P=761, Q=4591, W=250).
#[derive(Copy, Clone, Debug)]
pub struct Ntruplr761;

impl Params for Ntruplr761 {
    const P: usize = 761;
    const Q: i16 = 4591;
    const W: usize = 250;
    const PK_BYTES: usize = 32 + rq_rounded_bytes(761, 4591);
    const SK_BYTES: usize = r3_encoded_bytes(761) + Self::PK_BYTES + 32 + 32;
    const CT_BYTES: usize = rq_rounded_bytes(761, 4591) + 128 + 32;
    const SS_BYTES: usize = 32;
    const C_COUNT: usize = 256;
    const TAU0: i32 = 2156;
    const TAU1: i32 = 114;
    const TAU2: i32 = 2007;
    const TAU3: i32 = 287;
}

/// NTRUPLR parameter set: ntruplr653 (P=653, Q=4621, W=252).
#[derive(Copy, Clone, Debug)]
pub struct Ntruplr653;

impl Params for Ntruplr653 {
    const P: usize = 653;
    const Q: i16 = 4621;
    const W: usize = 252;
    const PK_BYTES: usize = 32 + rq_rounded_bytes(653, 4621);
    const SK_BYTES: usize = r3_encoded_bytes(653) + Self::PK_BYTES + 32 + 32;
    const CT_BYTES: usize = rq_rounded_bytes(653, 4621) + 128 + 32;
    const SS_BYTES: usize = 32;
    const C_COUNT: usize = 256;
    const TAU0: i32 = 2175;
    const TAU1: i32 = 113;
    const TAU2: i32 = 2031;
    const TAU3: i32 = 290;
}
