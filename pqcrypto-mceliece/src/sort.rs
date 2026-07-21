/// Constant-time sorting networks for McEliece secret data.
///
/// ## CT analysis: `uint64_sort`
///
/// Batcher's odd-even mergesort using arithmetic min/max pairs. All loop
/// bounds are derived from `n` (array length — a compile-time constant for
/// all call sites), not from element values. The comparison function
/// `uint64_minmax_pair` uses only arithmetic operations (`wrapping_sub`,
/// shifts, XOR) — no branches, no data-dependent control flow.
///
/// This is safe for sorting secret-derived data because:
/// - The number of comparisons is fixed for a given `n`.
/// - The comparison order is fixed (a Batcher network).
/// - No element is ever compared to itself based on its value.
///
/// The name `uint64_sort` follows the original C reference naming.
/// Verified 2026-06-15: constant-time against value-level timing side
/// channels. All loop bounds depend only on `n`, never on `values[]`.
///
/// Constant-time sorting network for `[i32]`. Loop bounds depend only on the
/// array length `n` (a compile-time constant at all call sites), never on
/// element values. Comparison uses `int32_minmax_pair`, which is branch-free.
/// Safe for secret-derived data.
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
