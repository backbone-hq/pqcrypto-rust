//! GF(2⁸) arithmetic for the Reed-Solomon code.
//! Uses primitive polynomial 0x11D (x⁸ + x⁴ + x³ + x² + 1).

/// Multiply two elements in GF(2⁸) under polynomial 0x11D.
#[inline]
pub(crate) fn gf_mul(a: u16, b: u16) -> u16 {
    // SAFETY: GF(2⁸) values are always < 256; truncation is intentional
    let a = u8::try_from(a).expect("GF(2^8) value fits in u8");
    let b = u8::try_from(b).expect("GF(2^8) value fits in u8");
    // carryless multiply of two 8-bit values → 16-bit result
    let c = carryless_mul8(a, b);
    // reduce modulo 0x11D (x⁸ + x⁴ + x³ + x² + 1)
    gf_reduce_8(c)
}

/// Compute the inverse of an element in GF(2⁸). If a == 0, returns 0.
#[inline]
pub(crate) fn gf_inverse(a: u16) -> u16 {
    if a == 0 {
        return 0;
    }
    // Addition chain: 1 2 3 4 7 11 15 30 60 120 127 254
    let a2 = gf_mul(a, a); // a^2
    let a3 = gf_mul(a2, a); // a^3
    let a4 = gf_mul(a2, a2); // a^4
    let a7 = gf_mul(a4, a3); // a^7
    let a11 = gf_mul(a7, a4); // a^11
    let a15 = gf_mul(a11, a4); // a^15
    let a30 = gf_mul(a15, a15); // a^30
    let a60 = gf_mul(a30, a30); // a^60
    let a120 = gf_mul(a60, a60); // a^120
    let a127 = gf_mul(a120, a7); // a^127
    gf_mul(a127, a127) // a^254 = a^(-1)
}

/// Carryless multiply of two 8-bit values (result is 16 bits).
/// Algorithm from HQC reference: mul1 with s=2, w=8.
#[inline]
fn carryless_mul8(a: u8, b: u8) -> u16 {
    let mut h: u16 = 0;

    // u[0]=0, u[1]=b & 0x7F, u[2]=u[1]<<1, u[3]=u[2]^u[1]
    let u1 = u16::from(b & 0x7F);
    let u = [0u16, u1, u1 << 1, (u1 << 1) ^ u1];

    // Step 1: process bits 0-1 of a
    let mut g = match (a & 0x03) as usize {
        0 => 0,
        1 => u[1],
        2 => u[2],
        _ => u[3],
    };
    let mut l = g;

    // Step 2: process bits 2,4,6 in 2-bit chunks
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

    // Step 3: handle the high bit of b
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
    // Unrolled: at most 2 iterations needed for 16-bit input
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
        // Spot-check known values
        assert_eq!(gf_mul(1, 2), 2);
        assert_eq!(gf_mul(2, 2), 4);
        // 0x80 * 2 = 0x100 → reduced by 0x11D
        // 0x100 ^ 0x11D = 0x01D = 29
        assert_eq!(gf_mul(0x80, 0x02), 0x1D);
    }
}
