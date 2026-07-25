//! Constant-time comparison utilities.
//!
//! Standard comparisons can compile to conditional jumps that leak operand
//! ordering via timing. These functions use only arithmetic and bitwise
//! operations so the execution path is independent of the input values.
//!
//! For signed integers we flip the sign bit to convert two's complement
//! into unsigned ordering, then delegate to `subtle`'s unsigned CT traits.
//! For unsigned integers we delegate directly to `subtle`.

use subtle::{
    Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
};

/// `Choice::from(1)` iff `a < b`.
#[inline]
#[must_use]
#[allow(clippy::cast_sign_loss)]
pub fn ct_lt_i32(a: i32, b: i32) -> Choice {
    let a_u = (a as u32) ^ (1u32 << 31);
    let b_u = (b as u32) ^ (1u32 << 31);
    a_u.ct_lt(&b_u)
}

/// `Choice::from(1)` iff `a <= b`.
#[inline]
#[must_use]
pub fn ct_le_i32(a: i32, b: i32) -> Choice {
    !ct_lt_i32(b, a)
}

/// `Choice::from(1)` iff `a > b`.
#[inline]
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn ct_gt_usize(a: usize, b: usize) -> Choice {
    if usize::BITS == 64 {
        (a as u64).ct_gt(&(b as u64))
    } else {
        (a as u32).ct_gt(&(b as u32))
    }
}

/// `Choice::from(1)` iff `a < b`.
#[inline]
#[must_use]
pub fn ct_lt_usize(a: usize, b: usize) -> Choice {
    ct_gt_usize(b, a)
}

/// CT count of elements ≠ `zero`. Branching per element would reveal support
/// patterns of secret vectors.
pub fn ct_count_nonzero<T: ConstantTimeEq>(values: &[T], zero: &T) -> usize {
    let mut count = 0usize;
    for v in values {
        let is_nonzero = v.ct_ne(zero);
        let inc = u8::conditional_select(&0u8, &1u8, is_nonzero) as usize;
        count += inc;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_lt_i32() {
        assert_eq!(ct_lt_i32(-5, 3).unwrap_u8(), 1);
        assert_eq!(ct_lt_i32(3, -5).unwrap_u8(), 0);
        assert_eq!(ct_lt_i32(0, 0).unwrap_u8(), 0);
        assert_eq!(ct_lt_i32(i32::MIN, i32::MAX).unwrap_u8(), 1);
        assert_eq!(ct_lt_i32(i32::MAX, i32::MIN).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_le_i32() {
        assert_eq!(ct_le_i32(3, 5).unwrap_u8(), 1);
        assert_eq!(ct_le_i32(5, 5).unwrap_u8(), 1);
        assert_eq!(ct_le_i32(7, 5).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_gt_usize() {
        assert_eq!(ct_gt_usize(5, 3).unwrap_u8(), 1);
        assert_eq!(ct_gt_usize(3, 5).unwrap_u8(), 0);
        assert_eq!(ct_gt_usize(0, 0).unwrap_u8(), 0);
        assert_eq!(ct_gt_usize(usize::MAX, 0).unwrap_u8(), 1);
    }

    #[test]
    fn test_ct_lt_usize() {
        assert_eq!(ct_lt_usize(3, 5).unwrap_u8(), 1);
        assert_eq!(ct_lt_usize(5, 5).unwrap_u8(), 0);
        assert_eq!(ct_lt_usize(7, 5).unwrap_u8(), 0);
    }

    #[test]
    fn test_ct_count_nonzero() {
        let values = [1i8, 0, 3, 0, 5];
        assert_eq!(ct_count_nonzero(&values, &0i8), 3);
        assert_eq!(ct_count_nonzero::<i8>(&[], &0), 0);
        assert_eq!(ct_count_nonzero(&[0i8, 0, 0], &0i8), 0);
    }

    #[test]
    fn test_ct_lt_i32_edges() {
        assert_eq!(ct_lt_i32(-5, 10).unwrap_u8(), 1);
        assert_eq!(ct_lt_i32(i32::MIN + 1, i32::MIN).unwrap_u8(), 0);
    }
}
