//! GF(2⁸) arithmetic for the Reed-Solomon code.
//! Uses primitive polynomial 0x11D (x⁸ + x⁴ + x³ + x² + 1).

#[inline]
pub(crate) fn gf_mul(a: u16, b: u16) -> u16 {
    // GF(2⁸) values are always < 256
    let a = u8::try_from(a).expect("GF(2^8) value fits in u8");
    let b = u8::try_from(b).expect("GF(2^8) value fits in u8");
    let c = carryless_mul8(a, b);
    gf_reduce_8(c)
}

#[inline]
pub(crate) fn gf_inverse(a: u16) -> u16 {
    if a == 0 {
        return 0;
    }
    let a2 = gf_mul(a, a);
    let a3 = gf_mul(a2, a);
    let a4 = gf_mul(a2, a2);
    let a7 = gf_mul(a4, a3);
    let a11 = gf_mul(a7, a4);
    let a15 = gf_mul(a11, a4);
    let a30 = gf_mul(a15, a15);
    let a60 = gf_mul(a30, a30);
    let a120 = gf_mul(a60, a60);
    let a127 = gf_mul(a120, a7);
    gf_mul(a127, a127)
}

/// Carryless multiply of two 8-bit values (result is 16 bits).
/// Algorithm from HQC reference: mul1 with s=2, w=8.
#[inline]
fn carryless_mul8(a: u8, b: u8) -> u16 {
    let mut h: u16 = 0;

    let u1 = u16::from(b & 0x7F);
    let u = [0u16, u1, u1 << 1, (u1 << 1) ^ u1];

    let mut g = match (a & 0x03) as usize {
        0 => 0,
        1 => u[1],
        2 => u[2],
        _ => u[3],
    };
    let mut l = g;

    let mut s = 2u16;
    while s < 8 {
        g = match ((a >> s) & 0x03) as usize {
            0 => 0,
            1 => u[1],
            2 => u[2],
            _ => u[3],
        };
        l ^= g << s;
        h ^= g >> (8 - s);
        s += 2;
    }

    if (b >> 7) & 1 != 0 {
        l ^= u16::from(a) << 7;
        h ^= u16::from(a) >> 1;
    }

    (h << 8) | l
}

/// Reduce a 16-bit polynomial modulo GF_POLY=0x11D.
/// Uses x⁸ = x⁴ + x³ + x² + 1 substitution iteratively.
#[inline]
fn gf_reduce_8(x: u16) -> u16 {
    let mut x = x;
    if x >= 256 {
        let high = x >> 8;
        x = (x & 0xFF) ^ high ^ (high << 4) ^ (high << 3) ^ (high << 2);
    }
    if x >= 256 {
        let high = x >> 8;
        x = (x & 0xFF) ^ high ^ (high << 4) ^ (high << 3) ^ (high << 2);
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mul_identity() {
        assert_eq!(gf_mul(0, 1), 0);
        for a in 1..=255u16 {
            assert_eq!(gf_mul(a, 1), a);
        }
    }

    #[test]
    fn test_gf_mul_zero() {
        assert_eq!(gf_mul(0, 42), 0);
        assert_eq!(gf_mul(42, 0), 0);
    }

    #[test]
    fn test_gf_inverse_roundtrip() {
        for a in 1..=255u16 {
            let inv = gf_inverse(a);
            assert!(inv != 0);
            assert_eq!(gf_mul(a, inv), 1, "a={}", a);
        }
    }

    #[test]
    fn test_gf_specific() {
        assert_eq!(gf_mul(1, 2), 2);
        assert_eq!(gf_mul(2, 2), 4);
        assert_eq!(gf_mul(0x80, 0x02), 0x1D);
    }
}
