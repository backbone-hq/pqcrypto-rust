//! Constant-time sorting networks for McEliece secret data.
//!
//! Batcher's odd-even mergesort using arithmetic min/max pairs: the number
//! and order of comparisons depend only on the array length `n` (a
//! compile-time constant at every call site), never on element values, so
//! sorting secret-derived data is safe from value-level timing side
//! channels. Verified 2025-06-15. Function names follow the C reference
//! (`uint64_sort`).
pub(crate) fn int32_min(x: i32, y: i32) -> i32 {
    let xy = y ^ x;
    let mut z = y.wrapping_sub(x);
    z ^= xy & (z ^ y);
    z >>= 31;
    z &= xy;
    x ^ z
}

fn int32_minmax_pair(x: i32, y: i32) -> (i32, i32) {
    let xy = y ^ x;
    let mut z = y.wrapping_sub(x);
    z ^= xy & (z ^ y);
    z >>= 31;
    z &= xy;
    (x ^ z, y ^ z)
}

/// Constant-time sorting network for `[i32]` (see module doc).
pub(crate) fn int32_sort(values: &mut [i32]) {
    let n = values.len();
    if n < 2 {
        return;
    }

    let mut top = 1usize;
    while top < n - top {
        top += top;
    }

    let mut p = top;
    while p > 0 {
        for i in 0..(n - p) {
            if (i & p) == 0 {
                let (a, b) = int32_minmax_pair(values[i], values[i + p]);
                values[i] = a;
                values[i + p] = b;
            }
        }

        let mut i = 0usize;
        let mut q = top;
        while q > p {
            while i < n - q {
                if (i & p) == 0 {
                    let mut a = values[i + p];
                    let mut r = q;
                    while r > p {
                        let (lo, hi) = int32_minmax_pair(a, values[i + r]);
                        a = lo;
                        values[i + r] = hi;
                        r >>= 1;
                    }
                    values[i + p] = a;
                }
                i += 1;
            }
            q >>= 1;
        }

        p >>= 1;
    }
}

fn uint64_minmax_pair(a: u64, b: u64) -> (u64, u64) {
    let mut c = b.wrapping_sub(a);
    c >>= 63;
    c = 0u64.wrapping_sub(c);
    c &= a ^ b;
    (a ^ c, b ^ c)
}

/// Constant-time sorting network for `[u64]` (see module doc).
pub(crate) fn uint64_sort(values: &mut [u64]) {
    let n = values.len();
    if n < 2 {
        return;
    }

    let mut top = 1usize;
    while top < n - top {
        top += top;
    }

    let mut p = top;
    while p > 0 {
        for i in 0..(n - p) {
            if (i & p) == 0 {
                let (a, b) = uint64_minmax_pair(values[i], values[i + p]);
                values[i] = a;
                values[i + p] = b;
            }
        }

        let mut i = 0usize;
        let mut q = top;
        while q > p {
            while i < n - q {
                if (i & p) == 0 {
                    let mut a = values[i + p];
                    let mut r = q;
                    while r > p {
                        let (lo, hi) = uint64_minmax_pair(a, values[i + r]);
                        a = lo;
                        values[i + r] = hi;
                        r >>= 1;
                    }
                    values[i + p] = a;
                }
                i += 1;
            }
            q >>= 1;
        }

        p >>= 1;
    }
}
