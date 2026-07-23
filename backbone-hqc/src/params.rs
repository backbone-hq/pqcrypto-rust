//! HQC parameter sets — all 3 NIST security levels.
//!
//! Each variant defines vector sizes, error weights, and error-correcting
//! code parameters via the `Params` trait.

/// Helper: ceil division for compile-time constants
const fn ceil_div(a: usize, b: usize) -> usize {
    a.div_ceil(b)
}

/// HQC parameter set trait.
pub trait Params {
    /// Vector length in bits.
    const N: usize;
    /// Length of RM code word (bits).
    const N2: usize;
    /// Length of RS code word (bytes).
    const N1: usize;
    /// Length of concatenated code word (bits).
    const N1N2: usize;
    /// Weight of secret key vectors x, y.
    const OMEGA: usize;
    /// Weight of encryption noise vector e.
    const OMEGA_E: usize;
    /// Weight of encryption randomness vectors r1, r2.
    const OMEGA_R: usize;
    /// Error correction capacity of RS code.
    const DELTA: usize;
    /// RS information symbols (bytes).
    const K: usize;
    /// RS generator polynomial size.
    const G: usize;
    /// Additive FFT parameter (2^FFT >= DELTA+1).
    const FFT: usize;

    /// Vector size in 64-bit limbs.
    const VEC_N_SIZE_64: usize = ceil_div(Self::N, 64);
    /// Vector size in bytes.
    const VEC_N_SIZE_BYTES: usize = ceil_div(Self::N, 8);
    /// Key size for RS code (K bytes).
    const VEC_K_SIZE_BYTES: usize = Self::K;
    /// RS code word size in bytes.
    const VEC_N1_SIZE_BYTES: usize = Self::N1;
    /// Concatenated code word size in 64-bit limbs.
    const VEC_N1N2_SIZE_64: usize = ceil_div(Self::N1N2, 64);
    /// Concatenated code word size in bytes.
    const VEC_N1N2_SIZE_BYTES: usize = ceil_div(Self::N1N2, 8);

    /// Public key size in bytes.
    const PK_BYTES: usize = Self::SEED_BYTES + Self::VEC_N_SIZE_BYTES;
    /// Secret key size in bytes.
    const SK_BYTES: usize = <Self as Params>::PK_BYTES
        + <Self as Params>::SEED_BYTES
        + <Self as Params>::VEC_K_SIZE_BYTES
        + <Self as Params>::SEED_BYTES;
    /// Ciphertext size in bytes.
    const CT_BYTES: usize =
        Self::VEC_N_SIZE_BYTES + Self::VEC_N1N2_SIZE_BYTES + Self::SALT_SIZE_BYTES;
    /// Shared secret size in bytes.
    const SS_BYTES: usize = 32;

    /// Seed size in bytes.
    const SEED_BYTES: usize = 32;
    /// Salt size in bytes.
    const SALT_SIZE_BYTES: usize = 16;
    /// SHAKE-256 output size (512 bits).
    const SHAKE256_512_BYTES: usize = 64;
    /// Mask for the last 64-bit word of an N-bit vector.
    const RED_MASK: u64;
    /// Coefficients of the RS generator polynomial.
    const RS_POLY_COEFS: &'static [u8];

    /// Multiplicity for Reed-Muller repetition.
    const RM_MULTIPLICITY: usize = if Self::N2 % 128 == 0 {
        Self::N2 / 128
    } else {
        Self::N2 / 128 + 1
    };
}

/// HQC-1 parameter set (NIST Security Level 1, AES-128 equivalent).
#[derive(Copy, Clone, Debug)]
pub struct Hqc128;

impl Params for Hqc128 {
    const N: usize = 17669;
    const N1: usize = 46;
    const N2: usize = 384;
    const N1N2: usize = 17664;
    const OMEGA: usize = 66;
    const OMEGA_E: usize = 75;
    const OMEGA_R: usize = 75;
    const DELTA: usize = 15;
    const K: usize = 16;
    const G: usize = 31;
    const FFT: usize = 4;

    const RED_MASK: u64 = 0x1f;
    const RS_POLY_COEFS: &'static [u8] = &[
        89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67,
        118, 105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1,
    ];
}

/// HQC-3 parameter set (NIST Security Level 3, AES-192 equivalent).
#[derive(Copy, Clone, Debug)]
pub struct Hqc192;

impl Params for Hqc192 {
    const N: usize = 35851;
    const N1: usize = 56;
    const N2: usize = 640;
    const N1N2: usize = 35840;
    const OMEGA: usize = 100;
    const OMEGA_E: usize = 114;
    const OMEGA_R: usize = 114;
    const DELTA: usize = 16;
    const K: usize = 24;
    const G: usize = 33;
    const FFT: usize = 5;

    const RED_MASK: u64 = 0x7ff;
    const RS_POLY_COEFS: &'static [u8] = &[
        45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1,
        238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1,
    ];
}

/// HQC-5 parameter set (NIST Security Level 5, AES-256 equivalent).
#[derive(Copy, Clone, Debug)]
pub struct Hqc256;

impl Params for Hqc256 {
    const N: usize = 57637;
    const N1: usize = 90;
    const N2: usize = 640;
    const N1N2: usize = 57600;
    const OMEGA: usize = 131;
    const OMEGA_E: usize = 149;
    const OMEGA_R: usize = 149;
    const DELTA: usize = 29;
    const K: usize = 32;
    const G: usize = 59;
    const FFT: usize = 5;

    const RED_MASK: u64 = 0x1fffffffff;
    const RS_POLY_COEFS: &'static [u8] = &[
        49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71,
        201, 115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4,
        246, 191, 144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hqc128_vec_size() {
        assert_eq!(<Hqc128 as Params>::VEC_N_SIZE_64, 277);
        assert_eq!(<Hqc128 as Params>::VEC_N_SIZE_BYTES, 2209);
        assert_eq!(<Hqc128 as Params>::VEC_N1N2_SIZE_64, 276);
        assert_eq!(<Hqc128 as Params>::VEC_N1N2_SIZE_BYTES, 2208);
        assert_eq!(<Hqc128 as Params>::VEC_K_SIZE_BYTES, 16);
        assert_eq!(<Hqc128 as Params>::VEC_N1_SIZE_BYTES, 46);
    }

    #[test]
    fn test_hqc192_vec_size() {
        assert_eq!(<Hqc192 as Params>::VEC_N_SIZE_64, 561);
        assert_eq!(<Hqc192 as Params>::VEC_N_SIZE_BYTES, 4482);
        assert_eq!(<Hqc192 as Params>::VEC_N1N2_SIZE_64, 560);
        assert_eq!(<Hqc192 as Params>::VEC_N1N2_SIZE_BYTES, 4480);
    }

    #[test]
    fn test_hqc256_vec_size() {
        assert_eq!(<Hqc256 as Params>::VEC_N_SIZE_64, 901);
        assert_eq!(<Hqc256 as Params>::VEC_N_SIZE_BYTES, 7205);
        assert_eq!(<Hqc256 as Params>::VEC_N1N2_SIZE_64, 900);
        assert_eq!(<Hqc256 as Params>::VEC_N1N2_SIZE_BYTES, 7200);
    }

    #[test]
    fn test_key_sizes() {
        assert_eq!(<Hqc128 as Params>::PK_BYTES, 2241);
        assert_eq!(<Hqc128 as Params>::SK_BYTES, 2321);
        assert_eq!(<Hqc128 as Params>::CT_BYTES, 4433);
        assert_eq!(<Hqc192 as Params>::PK_BYTES, 4514);
        assert_eq!(<Hqc192 as Params>::SK_BYTES, 4602);
        assert_eq!(<Hqc192 as Params>::CT_BYTES, 8978);
        assert_eq!(<Hqc256 as Params>::PK_BYTES, 7237);
        assert_eq!(<Hqc256 as Params>::SK_BYTES, 7333);
        assert_eq!(<Hqc256 as Params>::CT_BYTES, 14421);
    }
}
