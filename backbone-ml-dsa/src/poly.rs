#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
// All casts in this module operate on bounded values (byte/limb extraction, loop counters).
use crate::field::Q;
use backbone_pqcrypto_internals::secret::SecretArray;

#[derive(Clone)]
pub(crate) struct Poly {
    pub coeffs: SecretArray<i32, 256>,
}

impl Default for Poly {
    fn default() -> Self {
        Self::new()
    }
}

impl Poly {
    pub(crate) fn new() -> Self {
        Self {
            coeffs: SecretArray::new(),
        }
    }

    pub(crate) fn add(&mut self, other: &Poly) {
        for i in 0..256 {
            self.coeffs[i] += other.coeffs[i];
        }
    }

    pub(crate) fn sub(&mut self, other: &Poly) {
        for i in 0..256 {
            self.coeffs[i] -= other.coeffs[i];
        }
    }

    /// FIPS 204 Algorithm 34 (Decompose) with a compile-time `ALPHA`.
    ///
    /// `ALPHA` is a const generic, so `r / ALPHA` strength-reduces to a
    /// magic multiply+shift (no hardware division on the secret path), and
    /// the two secret-dependent branches are replaced with arithmetic
    /// masking. Output is bit-identical to the reference decompose
    /// (verified against edge values and KATs).
    pub(crate) fn decompose<const ALPHA: usize>(r: i32) -> (i32, i32) {
        // Exact floor(r / ALPHA) via magic multiply+shift — no division
        // instruction on ANY target. (aarch64's LLVM cost model
        // keeps `sdiv` even for constant divisors, so `r / ALPHA` is not
        // sufficient there.) MAGIC = ceil(2^32 / ALPHA) and MAX_A1 =
        // (Q-1)/ALPHA are literals per parameter set; the `match` on the
        // const param folds away at monomorphization. Exactness for every
        // r in [0, Q) is proven by `test_decompose_matches_reference_all_r`.
        let (magic, max_a1) = match ALPHA {
            190_464 => (22_549u64, 44i32),
            // ML-DSA-65/87 share ALPHA = 523776.
            _ => (8_200u64, 16i32),
        };
        let alpha = ALPHA as i32;
        let a1 = ((r as u64 * magic) >> 32) as i32;
        let mut a0 = r - a1 * alpha;
        // Center a0 into (-ALPHA/2, ALPHA/2]: mask == -1 iff a0 > ALPHA/2.
        // (a0 == ALPHA/2 stays — FIPS 204 mod^± keeps the upper boundary;
        //  an off-by-one here made a0 == gamma2 wrongly center, bumping a1
        //  into the top interval and corrupting w1' reconstruction.)
        let center_mask = ((alpha / 2) - a0) >> 31;
        a0 -= alpha & center_mask;
        let a1 = a1 - center_mask;
        // Top-interval case (a1 >= max_a1): mask == -1 iff a1 >= MAX_A1.
        let special = (max_a1 - 1 - a1) >> 31;
        let a1 = a1 & !special;
        let a0 = (a0 & !special) | ((r - Q) & special);
        (a1, a0)
    }

    /// FIPS 204 Algorithm 35 (UseHint). Verify-only (public data), so the
    /// branches stay; `ALPHA` is a compile-time constant so the internal
    /// decompose and `max_bits` never emit hardware division.
    pub(crate) fn use_hint<const ALPHA: usize>(r: i32, hint: i32) -> i32 {
        let alpha = ALPHA as i32;
        let (a1, a0) = Self::decompose::<ALPHA>(r);
        if hint == 0 {
            return a1;
        }
        let max_bits = (Q - 1) / alpha - 1;
        if a0 > 0 {
            if a1 == max_bits {
                0
            } else {
                a1 + 1
            }
        } else if a1 == 0 {
            max_bits
        } else {
            a1 - 1
        }
    }

    pub(crate) fn power2round(r: i32, d: i32) -> (i32, i32) {
        // Branchless Power2Round (FIPS 204 §4.1), bit-identical to the
        // previous branchy form including the r0 == 2^(d-1) boundary.
        let r1 = (r + (1 << (d - 1)) - 1) >> d;
        let r0 = r - (r1 << d);
        (r1, r0)
    }

    pub(crate) fn infinity_norm(&self) -> i32 {
        let mut max_val = 0i32;
        for &c in self.coeffs.iter() {
            // CT absolute value: (x ^ (x >> 31)) - (x >> 31) = |x|
            let abs_c = (c ^ (c >> 31)).wrapping_sub(c >> 31);
            // CT centered reduction: if abs_c > Q/2 then use Q - abs_c
            let mask = (Q.wrapping_sub(abs_c << 1)) >> 31;
            let centered = (mask & (Q - abs_c)) | (!mask & abs_c);
            // CT max: update max_val = max(max_val, centered)
            let update_mask = (max_val.wrapping_sub(centered)) >> 31;
            max_val ^= update_mask & (max_val ^ centered);
        }
        max_val
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 204 Algorithm 34 (Decompose), reference (branchy) form — the
    /// ground truth the constant-time version must match bit-for-bit.
    fn decompose_reference(r: i32, alpha: i32) -> (i32, i32) {
        let mut a1 = r / alpha;
        let mut a0 = r - a1 * alpha;
        // Center into (-ALPHA/2, ALPHA/2]: keep a0 == ALPHA/2 (FIPS mod^±).
        if a0 > alpha / 2 {
            a0 -= alpha;
            a1 += 1;
        }
        let max_a1 = (Q - 1) / alpha;
        if a1 >= max_a1 {
            return (0, r - Q);
        }
        (a1, a0)
    }

    #[test]
    fn test_decompose_matches_reference_all_r() {
        // Exhaustive over the full coefficient domain for both ALPHA values:
        // proves the magic multiply+shift and the arithmetic masking are
        // bit-identical to the reference decompose.
        for r in 0..Q {
            let expect = decompose_reference(r, 190_464);
            let got = Poly::decompose::<190_464>(r);
            assert_eq!(
                got, expect,
                "decompose mismatch at r={r} alpha=190464: got {got:?}, want {expect:?}"
            );
            let expect = decompose_reference(r, 523_776);
            let got = Poly::decompose::<523_776>(r);
            assert_eq!(
                got, expect,
                "decompose mismatch at r={r} alpha=523776: got {got:?}, want {expect:?}"
            );
        }
    }

    #[test]
    fn test_power2round_matches_reference_all_r() {
        // Exhaustive over the full coefficient domain for both D values:
        // proves the branchless Power2Round is bit-identical to the previous
        // branchy form, including the r0 == 2^(d-1) boundary (W1 fix safety).
        let branchy = |r: i32, d: i32| {
            let mask = (1 << d) - 1;
            let r0_raw = r & mask;
            let r0 = if r0_raw > (1 << (d - 1)) {
                r0_raw - (1 << d)
            } else {
                r0_raw
            };
            let r1 = (r - r0) >> d;
            (r1, r0)
        };
        for d in [13i32, 14] {
            for r in -Q..Q {
                let expect = branchy(r, d);
                let got = Poly::power2round(r, d);
                assert_eq!(
                    got, expect,
                    "power2round mismatch at r={r} d={d}: got {got:?}, want {expect:?}"
                );
            }
        }
    }

    #[test]
    fn test_poly_add_sub() {
        let mut p1 = Poly::new();
        p1.coeffs[0] = 1000;
        let mut p2 = Poly::new();
        p2.coeffs[0] = 500;

        let mut p3 = p1.clone();
        p3.add(&p2);
        assert_eq!(p3.coeffs[0], 1500);

        p3.sub(&p2);
        assert_eq!(p3.coeffs[0], 1000);
    }
}

#[cfg(test)]
mod ct_probe {
    #![allow(
        clippy::all,
        clippy::unwrap_used,
        clippy::cast_lossless,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        clippy::must_use_candidate,
        clippy::std_instead_of_alloc,
        clippy::std_instead_of_core
    )]
    use super::*;
    use alloc::vec::Vec;
    use backbone_pqcrypto_internals::testutil::XorShift;
    use std::{eprintln, println};

    fn enabled() -> bool {
        std::env::var("CT_VALIDATE").is_ok()
    }

    fn mean(v: &[u128]) -> f64 {
        v.iter().map(|&x| x as f64).sum::<f64>() / v.len() as f64
    }

    fn variance(v: &[u128], m: f64) -> f64 {
        v.iter()
            .map(|&x| {
                let d = x as f64 - m;
                d * d
            })
            .sum::<f64>()
            / (v.len() as f64 - 1.0)
    }

    fn welch_t(a: &[u128], b: &[u128]) -> f64 {
        let na = a.len() as f64;
        let nb = b.len() as f64;
        let ma = mean(a);
        let mb = mean(b);
        (ma - mb) / (variance(a, ma) / na + variance(b, mb) / nb).sqrt()
    }

    fn measure<F: FnMut() -> u64>(blocks: usize, per: usize, mut f: F) -> Vec<u128> {
        let mut out = Vec::with_capacity(blocks);
        for _ in 0..blocks {
            let t0 = std::time::Instant::now();
            let mut acc = 0u64;
            for _ in 0..per {
                acc = acc.wrapping_add(core::hint::black_box(f()));
            }
            core::hint::black_box(acc);
            out.push(t0.elapsed().as_nanos());
        }
        out
    }

    fn report(name: &str, a: &[u128], b: &[u128]) -> f64 {
        let t = welch_t(a, b);
        println!(
            "[CT-VALIDATE] {name}: welch_t={t:.1} classA_mean={:.1}ns classB_mean={:.1}ns",
            mean(a),
            mean(b)
        );
        t
    }

    /// Decompose runs `r / alpha` (hardware division) plus
    /// secret-dependent branches on r = w = A·y (secret mask). Pools are
    /// hidden behind black_box to stop opt-3 constant-folding; both classes
    /// pay identical array-read overhead.
    #[test]
    fn probe_decompose_alpha_190464() {
        if !enabled() {
            eprintln!("[CT-VALIDATE] ml-dsa probes skipped (set CT_VALIDATE=1)");
            return;
        }
        const N: usize = 256;
        let mut rng = XorShift::new();
        let _alpha = 190_464i32; // ML-DSA-44: 2*gamma2 (const arg below)
        let fixed: Vec<i32> = core::hint::black_box((0..N).map(|_| 0i32).collect());
        let random: Vec<i32> =
            core::hint::black_box((0..N).map(|_| (rng.next_u64() % Q as u64) as i32).collect());
        let mut ca = 0usize;
        let a = measure(4000, 1000, || {
            let r = fixed[ca & (N - 1)];
            ca += 1;
            let (h, l) = Poly::decompose::<190_464>(r);
            (h as u64) ^ (l as u64)
        });
        let mut cb = 0usize;
        let b = measure(4000, 1000, || {
            let r = random[cb & (N - 1)];
            cb += 1;
            let (h, l) = Poly::decompose::<190_464>(r);
            (h as u64) ^ (l as u64)
        });
        let t = report("ml-dsa decompose(alpha=190464)", &a, &b);
        let _ = t;
    }

    #[test]
    fn probe_decompose_alpha_523776() {
        if !enabled() {
            return;
        }
        const N: usize = 256;
        let mut rng = XorShift::new();
        let _alpha = 523_776i32; // ML-DSA-65/87: 2*gamma2 (const arg below)
        let fixed: Vec<i32> = core::hint::black_box((0..N).map(|_| 0i32).collect());
        let random: Vec<i32> =
            core::hint::black_box((0..N).map(|_| (rng.next_u64() % Q as u64) as i32).collect());
        let mut ca = 0usize;
        let a = measure(4000, 1000, || {
            let r = fixed[ca & (N - 1)];
            ca += 1;
            let (h, l) = Poly::decompose::<523_776>(r);
            (h as u64) ^ (l as u64)
        });
        let mut cb = 0usize;
        let b = measure(4000, 1000, || {
            let r = random[cb & (N - 1)];
            cb += 1;
            let (h, l) = Poly::decompose::<523_776>(r);
            (h as u64) ^ (l as u64)
        });
        let t = report("ml-dsa decompose(alpha=523776)", &a, &b);
        let _ = t;
    }
}
