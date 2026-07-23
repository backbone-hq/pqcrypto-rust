//! ML-DSA (FIPS 204) Field Operations
//! Operations modulo Q = 8380417.

pub(crate) const Q: i32 = 8380417;

/// Performs conditional subtraction of Q (brings to [0, Q-1]).
#[inline]
pub(crate) fn csubq(a: i32) -> i32 {
    let r = a.wrapping_sub(Q);
    r + ((r >> 31) & Q)
}

/// Performs conditional addition of Q if a < 0 (fixes negative only).
#[inline]
pub(crate) fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & Q)
}

/// Montgomery reduction: returns a * R^-1 mod Q.
/// R = 2^32.
#[inline]
pub(crate) fn montgomery_reduce(a: i64) -> i32 {
    // SAFETY: Montgomery reduction intentionally uses the lower 32 bits of `a`.
    let t = i32::from_le_bytes(a.to_le_bytes()[..4].try_into().expect("4 bytes from i64"))
        .wrapping_mul(QINV);
    let t = (a - i64::from(t) * i64::from(Q)) >> 32;
    i32::try_from(t).expect("value fits in i32")
}

/// reduce32: narrow a to approx [-6283008, 6283008] (matching C ref).
/// Used before invntt_tomont to keep coefficients in a safe range.
#[inline]
pub(crate) fn reduce32(a: i32) -> i32 {
    let t = (i64::from(a) + (1 << 22)) >> 23;
    // SAFETY: the result of (a - t*Q) for |a| < 2^31 and t = round(a/2^23)
    i32::try_from(i64::from(a) - t * i64::from(Q)).expect("value fits in i32")
}

const QINV: i32 = 58728449;

#[cfg(test)]
mod tests {
    use super::{montgomery_reduce, Q};

    #[test]
    fn test_field_reduction() {
        let a = 123456789i64;
        let a_scaled = a * (1i64 << 32);
        let r = montgomery_reduce(a_scaled);
        let q_i64 = i64::from(Q);
        let expected = a % q_i64;
        let actual = (i64::from(r) + q_i64) % q_i64;
        assert_eq!(
            actual, expected,
            "montgomery_reduce(123456789 * 2^32) failed: got r={}",
            r
        );
    }

    #[test]
    fn test_montgomery_reduce_simple() {
        let a: i64 = 1234;
        let a_scaled = a * (1i64 << 32);
        let r = montgomery_reduce(a_scaled);
        let q_i64 = i64::from(Q);
        let expected = a % q_i64;
        let actual = (i64::from(r) + q_i64) % q_i64;
        assert_eq!(actual, expected);
    }
}
