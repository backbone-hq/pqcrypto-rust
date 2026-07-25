use alloc::boxed::Box;
use alloc::vec;
use core::fmt;
use core::ops::{Deref, DerefMut, Index, IndexMut, Range, RangeTo};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A heap-allocated buffer that zeroizes its contents on drop.
///
/// Wraps a `Box<[T]>` and automatically zeroizes the backing buffer when the value
/// goes out of scope (requires `T: Zeroize`).  The fixed-length slice prevents
/// accidental reallocation that could leak un-zeroized heap memory.
pub struct SecretVec<T: Zeroize>(Box<[T]>);

impl<T: Zeroize> fmt::Debug for SecretVec<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretVec")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl<T: Zeroize> Zeroize for SecretVec<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> Drop for SecretVec<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[allow(missing_docs)]
impl<T: Zeroize> SecretVec<T> {
    #[must_use]
    pub fn new(len: usize) -> Self
    where
        T: Clone + Default,
    {
        SecretVec(vec![T::default(); len].into_boxed_slice())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T: Zeroize> Deref for SecretVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T: Zeroize> DerefMut for SecretVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.0
    }
}

impl<T: Zeroize + Clone> Clone for SecretVec<T> {
    fn clone(&self) -> Self {
        SecretVec(self.0.clone())
    }
}

/// A fixed-size array that zeroizes its contents on drop.
///
/// Wraps a `[T; N]` and automatically zeroizes the backing array when the value
/// goes out of scope (requires `T: Zeroize`).  Access elements via deref coercion
/// or standard array indexing.
pub struct SecretArray<T: Zeroize, const N: usize>(pub(crate) [T; N]);

impl<T: Zeroize, const N: usize> fmt::Debug for SecretArray<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretArray").field(&N).finish()
    }
}

impl<T: Zeroize, const N: usize> Zeroize for SecretArray<T, N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize, const N: usize> Drop for SecretArray<T, N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[allow(missing_docs)]
impl<T: Zeroize + Clone + Default, const N: usize> SecretArray<T, N> {
    #[must_use]
    pub fn new() -> Self {
        SecretArray(array_from_default::<T, N>())
    }

    /// Create a `SecretArray` from an existing fixed-size array.
    #[must_use]
    pub fn from_array(arr: [T; N]) -> Self {
        SecretArray(arr)
    }
}

impl<T: Zeroize, const N: usize> SecretArray<T, N> {
    /// Consume and return the inner array without zeroizing.
    ///
    /// Uses `core::mem::replace` with a zeroed default, leaving the
    /// original (now-zeroed) array for Drop to handle harmlessly.
    /// Only available when `T: Default`.
    #[must_use]
    pub fn into_inner(mut self) -> [T; N]
    where
        T: Default,
    {
        let zeroed: [T; N] = core::array::from_fn(|_| T::default());
        core::mem::replace(&mut self.0, zeroed)
    }
}

impl<T: Zeroize + Default, const N: usize> Default for SecretArray<T, N> {
    fn default() -> Self {
        SecretArray(array_from_default::<T, N>())
    }
}

impl<T: Zeroize, const N: usize> Deref for SecretArray<T, N> {
    type Target = [T; N];
    fn deref(&self) -> &[T; N] {
        &self.0
    }
}

impl<T: Zeroize, const N: usize> DerefMut for SecretArray<T, N> {
    fn deref_mut(&mut self) -> &mut [T; N] {
        &mut self.0
    }
}

impl<T: Zeroize, const N: usize> Index<usize> for SecretArray<T, N> {
    type Output = T;
    fn index(&self, idx: usize) -> &T {
        &self.0[idx]
    }
}

impl<T: Zeroize, const N: usize> IndexMut<usize> for SecretArray<T, N> {
    fn index_mut(&mut self, idx: usize) -> &mut T {
        &mut self.0[idx]
    }
}

impl<T: Zeroize, const N: usize> Index<Range<usize>> for SecretArray<T, N> {
    type Output = [T];
    fn index(&self, idx: Range<usize>) -> &[T] {
        &self.0[idx]
    }
}

impl<T: Zeroize, const N: usize> IndexMut<Range<usize>> for SecretArray<T, N> {
    fn index_mut(&mut self, idx: Range<usize>) -> &mut [T] {
        &mut self.0[idx]
    }
}

impl<T: Zeroize, const N: usize> Index<RangeTo<usize>> for SecretArray<T, N> {
    type Output = [T];
    fn index(&self, idx: RangeTo<usize>) -> &[T] {
        &self.0[idx]
    }
}

impl<T: Zeroize, const N: usize> IndexMut<RangeTo<usize>> for SecretArray<T, N> {
    fn index_mut(&mut self, idx: RangeTo<usize>) -> &mut [T] {
        &mut self.0[idx]
    }
}

impl<T: Zeroize + Clone, const N: usize> Clone for SecretArray<T, N> {
    fn clone(&self) -> Self {
        SecretArray(self.0.clone())
    }
}

impl<T: Zeroize + PartialEq, const N: usize> PartialEq for SecretArray<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Zeroize + Eq, const N: usize> Eq for SecretArray<T, N> {}

impl<const N: usize> ConstantTimeEq for SecretArray<u8, N> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<T: Zeroize, const N: usize> AsRef<[T]> for SecretArray<T, N> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T: Zeroize, const N: usize> AsMut<[T]> for SecretArray<T, N> {
    fn as_mut(&mut self) -> &mut [T] {
        &mut self.0
    }
}

fn array_from_default<T: Default, const N: usize>() -> [T; N] {
    [(); N].map(|_| T::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use subtle::ConstantTimeEq;

    #[test]
    fn test_debug_secretvec_redacts() {
        let mut s = SecretVec::new(8);
        #[allow(clippy::cast_possible_truncation)]
        for (i, b) in s.iter_mut().enumerate() {
            *b = 0xABu8.wrapping_add(i as u8);
        }
        let d = format!("{:?}", s);
        assert!(d.starts_with("SecretVec"), "type name should appear");
        assert!(d.contains("len: 8"), "metadata should appear");
        assert!(!d.contains("171"), "no byte values in output");
        assert!(d.contains(".."), "redaction indicator should appear");
    }

    #[test]
    fn test_debug_secretarray_redacts() {
        let mut a = SecretArray::<u8, 16>::new();
        #[allow(clippy::cast_possible_truncation)]
        for (i, b) in a.iter_mut().enumerate() {
            *b = 0xCDu8.wrapping_add(i as u8);
        }
        let d = format!("{:?}", a);
        assert!(d.starts_with("SecretArray"), "type name should appear");
        assert!(!d.contains("205"), "no byte values in output");
    }

    #[test]
    fn test_secretvec_is_fixed_length() {
        let sv = SecretVec::<u8>::new(16);
        assert_eq!(sv.len(), 16);
    }

    #[test]
    fn test_secretvec_indexed_writes_work() {
        let mut sv = SecretVec::<u8>::new(4);
        sv[0] = 10;
        sv[3] = 20;
        assert_eq!(sv[0], 10);
        assert_eq!(sv[3], 20);
    }

    #[test]
    fn test_secretvec_iter_mut_works() {
        let mut sv = SecretVec::<u8>::new(4);
        #[allow(clippy::cast_possible_truncation)]
        for (i, b) in sv.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(&sv[..], &[0, 1, 2, 3]);
    }

    #[test]
    fn test_secretvec_zeroize_clears() {
        let mut sv = SecretVec::<u8>::new(8);
        sv[0] = 42;
        sv.zeroize();
        assert!(sv.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secretarray_ct_eq_equal() {
        let a = SecretArray::<u8, 8>::new();
        let b = SecretArray::<u8, 8>::new();
        assert_eq!(a.ct_eq(&b).unwrap_u8(), 1);
    }

    #[test]
    fn test_secretarray_ct_eq_different() {
        let a = SecretArray::<u8, 8>::new();
        let mut b = SecretArray::<u8, 8>::new();
        b[0] = 1;
        assert_eq!(a.ct_eq(&b).unwrap_u8(), 0);
    }

    #[test]
    fn test_secretarray_ct_eq_no_short_circuit() {
        let a = SecretArray::<u8, 8>::new();
        let mut b = SecretArray::<u8, 8>::new();
        b[7] = 1;
        assert_eq!(a.ct_eq(&b).unwrap_u8(), 0);
    }

    #[test]
    fn test_secretarray_ct_eq_u8_array() {
        let mut a = SecretArray::<u8, 16>::new();
        let mut b = SecretArray::<u8, 16>::new();
        for i in 0..16 {
            // i < 16, well within u8 range
            a[i] = u8::try_from(i).unwrap();
            b[i] = u8::try_from(i).unwrap();
        }
        assert_eq!(a.ct_eq(&b).unwrap_u8(), 1);
        b[10] ^= 0xFF;
        assert_eq!(a.ct_eq(&b).unwrap_u8(), 0);
    }

    #[test]
    fn test_secretarray_partial_eq_short_circuits() {
        let a = SecretArray::<u8, 8>::new();
        let mut b = SecretArray::<u8, 8>::new();
        b[7] = 1;
        assert_ne!(a, b);
    }
}
