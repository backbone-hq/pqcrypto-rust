//! Parameter constants for SNTRUP variants.
//! Defines the `Params` trait and the `Sntrup761` implementation.

/// Trait providing parameter constants for an SNTRUP parameter set.
pub trait Params {
    /// Ring dimension (x^p - x - 1).
    const P: usize;
    /// Field modulus for Rq (Z/qZ).
    const Q: i16;
    /// Small polynomial weight (Hamming weight in R3).
    const W: usize;
    /// Public key size in bytes.
    const PK_BYTES: usize;
    /// Secret key size in bytes.
    const SK_BYTES: usize;
    /// Ciphertext size in bytes.
    const CT_BYTES: usize;
    /// Shared secret size in bytes.
    const SS_BYTES: usize;
}

/// Streamlined NTRU Prime sntrup761 parameter set.
///
/// - Ring: Z/4591Z`[x]`/(x^761 - x - 1)
/// - Small-polynomial weight: 286
/// - PK: 1158 bytes, SK: 1763 bytes, CT: 1039 bytes, SS: 32 bytes
#[derive(Copy, Clone, Debug)]
pub struct Sntrup761;

impl Params for Sntrup761 {
    const P: usize = 761;
    const Q: i16 = 4591;
    const W: usize = 286;
    const PK_BYTES: usize = 1158;
    const SK_BYTES: usize = 1763;
    const CT_BYTES: usize = 1039;
    const SS_BYTES: usize = 32;
}

/// Streamlined NTRU Prime sntrup653 parameter set.
///
/// - Ring: Z/4621Z`[x]`/(x^653 - x - 1)
/// - Small-polynomial weight: 288
#[derive(Copy, Clone, Debug)]
pub struct Sntrup653;

impl Params for Sntrup653 {
    const P: usize = 653;
    const Q: i16 = 4621;
    const W: usize = 288;
    const PK_BYTES: usize = 994;
    const SK_BYTES: usize = 1518;
    const CT_BYTES: usize = 897;
    const SS_BYTES: usize = 32;
}

/// Streamlined NTRU Prime sntrup857 parameter set.
///
/// - Ring: Z/5167Z`[x]`/(x^857 - x - 1)
/// - Small-polynomial weight: 322
#[derive(Copy, Clone, Debug)]
pub struct Sntrup857;

impl Params for Sntrup857 {
    const P: usize = 857;
    const Q: i16 = 5167;
    const W: usize = 322;
    const PK_BYTES: usize = 1322;
    const SK_BYTES: usize = 1999;
    const CT_BYTES: usize = 1184;
    const SS_BYTES: usize = 32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sntrup761_params() {
        assert_eq!(<Sntrup761 as Params>::P, 761);
        assert_eq!(<Sntrup761 as Params>::Q, 4591);
        assert_eq!(<Sntrup761 as Params>::W, 286);
        assert_eq!(<Sntrup761 as Params>::PK_BYTES, 1158);
        assert_eq!(<Sntrup761 as Params>::SK_BYTES, 1763);
        assert_eq!(<Sntrup761 as Params>::CT_BYTES, 1039);
        assert_eq!(<Sntrup761 as Params>::SS_BYTES, 32);
    }
}
