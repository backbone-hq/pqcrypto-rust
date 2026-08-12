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
    // The exponentiation chain computes a^(2^8-2), which is 0 for a == 0 and
    // the inverse otherwise — so the data-dependent early return is removed
    // with no change in output.
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
/// Branchless selection of u[t] for t in 0..=3 where
/// u = [0, u1, 2*u1, 2*u1 ^ u1] — replaces the secret-operand `match`
/// (which compiled to an indirect jump table) with arithmetic masks.
#[inline]
fn mul1_select(u1: u16, t: u16) -> u16 {
    let hi = 0u16.wrapping_sub((t >> 1) & 1);
    let lo = 0u16.wrapping_sub(t & 1);
    ((u1 << 1) & hi) ^ (u1 & lo)
}

#[inline]
fn carryless_mul8(a: u8, b: u8) -> u16 {
    let mut h: u16 = 0;

    let u1 = u16::from(b & 0x7F);

    let mut g = mul1_select(u1, u16::from(a & 0x03));
    let mut l = g;

    let mut s = 2u16;
    while s < 8 {
        g = mul1_select(u1, u16::from((a >> s) & 0x03));
        l ^= g << s;
        h ^= g >> (8 - s);
        s += 2;
    }

    // Masked (branchless) top-bit contribution.
    let m = 0u16.wrapping_sub(u16::from((b >> 7) & 1));
    l ^= (u16::from(a) << 7) & m;
    h ^= (u16::from(a) >> 1) & m;

    (h << 8) | l
}

/// Reduce a 16-bit polynomial modulo GF_POLY=0x11D.
/// Uses x⁸ = x⁴ + x³ + x² + 1 substitution iteratively.
#[inline]
fn gf_reduce_8(x: u16) -> u16 {
    // The two reduction substitutions are applied unconditionally. When
    // `high` is already 0 the extra pass is a no-op,
    // so this is bit-identical to the conditional form (no data-dependent
    // branches).
    let mut x = x;
    let high = x >> 8;
    x = (x & 0xFF) ^ high ^ (high << 4) ^ (high << 3) ^ (high << 2);
    let high = x >> 8;
    x = (x & 0xFF) ^ high ^ (high << 4) ^ (high << 3) ^ (high << 2);
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

    /// `gf_mul` uses `match` on secret operands that compiles to an
    /// indirect jump table. Class A = fixed operands, B = random pool.
    #[test]
    fn probe_gf_mul() {
        if !enabled() {
            eprintln!("[CT-VALIDATE] hqc gf probes skipped (set CT_VALIDATE=1)");
            return;
        }
        const N: usize = 256;
        let mut rng = XorShift::new();
        let fa: Vec<u16> = core::hint::black_box((0..N).map(|_| 1u16).collect());
        let fb: Vec<u16> = core::hint::black_box((0..N).map(|_| 1u16).collect());
        let ra: Vec<u16> =
            core::hint::black_box((0..N).map(|_| (rng.next_u64() & 0xFF) as u16).collect());
        let rb: Vec<u16> =
            core::hint::black_box((0..N).map(|_| (rng.next_u64() & 0xFF) as u16).collect());
        let mut ca = 0usize;
        let a = measure(2000, 1000, || {
            let (x, y) = (fa[ca & (N - 1)], fb[ca & (N - 1)]);
            ca += 1;
            u64::from(gf_mul(x, y))
        });
        let mut cb = 0usize;
        let b = measure(2000, 1000, || {
            let (x, y) = (ra[cb & (N - 1)], rb[cb & (N - 1)]);
            cb += 1;
            u64::from(gf_mul(x, y))
        });
        let t = report("hqc gf_mul (match/jump table)", &a, &b);
        let _ = t;
    }

    /// `gf_inverse` early-returns on a == 0.
    #[test]
    fn probe_gf_inverse() {
        if !enabled() {
            return;
        }
        const N: usize = 256;
        let mut rng = XorShift::new();
        let fixed: Vec<u16> = core::hint::black_box((0..N).map(|_| 0u16).collect());
        let random: Vec<u16> = core::hint::black_box(
            (0..N)
                .map(|_| ((rng.next_u64() % 255) + 1) as u16)
                .collect(),
        );
        let mut ca = 0usize;
        let a = measure(2000, 1000, || {
            let x = fixed[ca & (N - 1)];
            ca += 1;
            u64::from(gf_inverse(x))
        });
        let mut cb = 0usize;
        let b = measure(2000, 1000, || {
            let x = random[cb & (N - 1)];
            cb += 1;
            u64::from(gf_inverse(x))
        });
        let t = report("hqc gf_inverse (early return)", &a, &b);
        let _ = t;
    }
}
