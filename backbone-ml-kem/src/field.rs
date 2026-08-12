/// Q = 3329 for ML-KEM
pub(crate) const Q: i32 = 3329;

/// R = 2^16 for Montgomery reduction
#[cfg(test)]
pub(crate) const R: i32 = 1 << 16;

/// QINV = -Q^{-1} mod R = -3327
/// Such that Q * QINV ≡ 1 (mod 2^16)
pub(crate) const QINV: i16 = -3327i16;

/// Montgomery reduction.
/// Given a in range [-Q*R/2, Q*R/2], returns r in [-Q+1, Q-1] with r ≡ a * R^{-1} (mod Q).
/// Extracts the low 16 bits; matches pq-crystals/kyber reference C on little-endian platforms.
#[inline]
pub(crate) fn montgomery_reduce(a: i32) -> i16 {
    let a_bytes = a.to_ne_bytes();
    let a_i16 = i16::from_ne_bytes([a_bytes[0], a_bytes[1]]);
    let t_raw = i32::from(a_i16).wrapping_mul(i32::from(QINV));
    let t_bytes = t_raw.to_ne_bytes();
    let t = i16::from_ne_bytes([t_bytes[0], t_bytes[1]]);
    let r = a.wrapping_sub(i32::from(t).wrapping_mul(Q)) >> 16;
    i16::try_from(r).expect("r in [-Q+1, Q-1] fits in i16")
}

/// Barrett reduction for i16.
/// Returns centered representative in [-(Q-1)/2, (Q-1)/2].
/// Matches reference: v = ((1<<26) + Q/2) / Q, t = (v*a + 1<<25) >> 26.
#[inline]
pub(crate) fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = 20159;
    let t = i16::try_from((V * i32::from(a) + (1 << 25)) >> 26)
        .expect("t = (V*a + 1<<25) >> 26 fits in i16");
    let q_i16 = i16::try_from(Q).expect("Q fits in i16");
    a - t * q_i16
}

/// Conditional subtract Q to bring a into [0, Q-1].
/// Valid for a in [0, 2Q-1].
#[inline]
pub(crate) fn csubq(a: i16) -> i16 {
    let mut a = a;
    let q_i16 = i16::try_from(Q).expect("Q fits in i16");
    a -= q_i16;
    a += (a >> 15) & q_i16;
    a
}

/// Batch csubq for all coefficients.
#[cfg(test)]
mod tests {
    #![allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss
    )]
    use super::*;

    #[test]
    fn test_montgomery_reduce_r() {
        for x in [0, 1, 2, 100, 3328, 1729, 2761] {
            let a = i32::from(x) * R;
            let r = montgomery_reduce(a);
            assert_eq!(csubq(r), x, "mont_reduce(x*R) failed for x={}", x);
        }
    }

    #[test]
    fn test_mul_consistent() {
        let a: i16 = 1234i16;
        let b: i16 = 567i16;
        let c: i16 = 89i16;
        let ab = montgomery_reduce(i32::from(a) * i32::from(b));
        let abc = montgomery_reduce(i32::from(ab) * i32::from(c));
        let bc = montgomery_reduce(i32::from(b) * i32::from(c));
        let abc2 = montgomery_reduce(i32::from(a) * i32::from(bc));
        assert_eq!(csubq(abc), csubq(abc2), "mul not associative");
    }

    #[test]
    fn test_montgomery_self_consistent() {
        let x: i16 = 1234;
        let mont_x = montgomery_reduce(i32::from(x).wrapping_mul(1353));
        let back = montgomery_reduce(i32::from(mont_x));
        assert_eq!(csubq(back), x, "Montgomery roundtrip failed for x={}", x);
    }

    #[test]
    fn test_barrett_reduce() {
        let vals = [0, 1, 100, 3328, 3329, 4000, 5000, 6657];
        for &v in &vals {
            let r = barrett_reduce(v);
            assert!(i32::from(r) >= -(Q - 1) / 2);
            assert!(i32::from(r) <= (Q - 1) / 2);
            let expected = v % (Q as i16);
            let got = (r % (Q as i16) + Q as i16) % Q as i16;
            assert_eq!(
                got, expected,
                "barrett_reduce({}) gave {} (expected {})",
                v, r, expected
            );
        }
    }

    #[test]
    fn test_csubq() {
        assert_eq!(csubq(0), 0);
        assert_eq!(csubq(1), 1);
        assert_eq!(csubq(3328), 3328);
        assert_eq!(csubq(3329), 0);
        assert_eq!(csubq(6657), 3328);
    }
}
