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
    /// Rounding constant used by top() (kem.rs).
    const TAU0: i32;
    /// Rounding constant used by top() (kem.rs).
    const TAU1: i32;
    /// Rounding constant used by right() (kem.rs).
    const TAU2: i32;
    /// Rounding constant used by right() (kem.rs).
    const TAU3: i32;
}

/// NTRU LPRime parameter set.
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

/// NTRU LPRime parameter set.
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

/// NTRU LPRime parameter set.
#[derive(Copy, Clone, Debug)]
pub struct Ntruplr857;

impl Params for Ntruplr857 {
    const P: usize = 857;
    const Q: i16 = 5167;
    const W: usize = 281;
    const PK_BYTES: usize = 32 + rq_rounded_bytes(857, 5167);
    const SK_BYTES: usize = r3_encoded_bytes(857) + Self::PK_BYTES + 32 + 32;
    const CT_BYTES: usize = rq_rounded_bytes(857, 5167) + 128 + 32;
    const SS_BYTES: usize = 32;
    const C_COUNT: usize = 256;
    const TAU0: i32 = 2433;
    const TAU1: i32 = 101;
    const TAU2: i32 = 2265;
    const TAU3: i32 = 324;
}

/// NTRU LPRime parameter set.
#[derive(Copy, Clone, Debug)]
pub struct Ntruplr953;

impl Params for Ntruplr953 {
    const P: usize = 953;
    const Q: i16 = 6343;
    const W: usize = 345;
    const PK_BYTES: usize = 32 + rq_rounded_bytes(953, 6343);
    const SK_BYTES: usize = r3_encoded_bytes(953) + Self::PK_BYTES + 32 + 32;
    const CT_BYTES: usize = rq_rounded_bytes(953, 6343) + 128 + 32;
    const SS_BYTES: usize = 32;
    const C_COUNT: usize = 256;
    const TAU0: i32 = 2997;
    const TAU1: i32 = 82;
    const TAU2: i32 = 2798;
    const TAU3: i32 = 400;
}

/// NTRU LPRime parameter set.
#[derive(Copy, Clone, Debug)]
pub struct Ntruplr1013;

impl Params for Ntruplr1013 {
    const P: usize = 1013;
    const Q: i16 = 7177;
    const W: usize = 392;
    const PK_BYTES: usize = 32 + rq_rounded_bytes(1013, 7177);
    const SK_BYTES: usize = r3_encoded_bytes(1013) + Self::PK_BYTES + 32 + 32;
    const CT_BYTES: usize = rq_rounded_bytes(1013, 7177) + 128 + 32;
    const SS_BYTES: usize = 32;
    const C_COUNT: usize = 256;
    const TAU0: i32 = 3367;
    const TAU1: i32 = 73;
    const TAU2: i32 = 3143;
    const TAU3: i32 = 449;
}

/// NTRU LPRime parameter set.
#[derive(Copy, Clone, Debug)]
pub struct Ntruplr1277;

impl Params for Ntruplr1277 {
    const P: usize = 1277;
    const Q: i16 = 7879;
    const W: usize = 429;
    const PK_BYTES: usize = 32 + rq_rounded_bytes(1277, 7879);
    const SK_BYTES: usize = r3_encoded_bytes(1277) + Self::PK_BYTES + 32 + 32;
    const CT_BYTES: usize = rq_rounded_bytes(1277, 7879) + 128 + 32;
    const SS_BYTES: usize = 32;
    const C_COUNT: usize = 256;
    const TAU0: i32 = 3724;
    const TAU1: i32 = 66;
    const TAU2: i32 = 3469;
    const TAU3: i32 = 496;
}
