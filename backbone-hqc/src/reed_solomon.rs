#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
// All casts in this module operate on bounded values (byte/limb extraction, loop counters).
//! Reed-Solomon code over GF(2⁸): systematic encoder and syndrome-based decoder.
//! The RS code has parameters (n1 = 2^M - 1 - (G - 1), k = K) correcting up to DELTA errors.
//! Decoder uses: Berlekamp-Massey (error locator polynomial), Chien search (root finding),
//! Forney formula (error values).

use crate::gf;
use crate::params::Params;
use backbone_pqcrypto_internals::ct::ct_gt_usize;
use backbone_pqcrypto_internals::secret::SecretVec;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Uses a linear (N1 - K)-stage shift register with feedback based on the
/// generator polynomial RS_POLY.
pub(crate) fn encode<P: Params>(cdw: &mut [u8], msg: &[u8]) {
    cdw.fill(0);

    for i in 0..P::K {
        let gate_value = msg[P::K - 1 - i] ^ cdw[P::N1 - P::K - 1];
        let mut tmp = [0u16; 64];
        for j in 0..P::G {
            tmp[j] = gf::gf_mul(u16::from(gate_value), u16::from(P::RS_POLY_COEFS[j]));
        }
        for k in (1..P::N1 - P::K).rev() {
            // tmp[k] is GF(2⁸) value < 256; mask makes truncation explicit
            cdw[k] = cdw[k - 1] ^ (tmp[k] & 0xFF) as u8;
        }
        // tmp[0] is GF(2⁸) value < 256; mask makes truncation explicit
        cdw[0] = (tmp[0] & 0xFF) as u8;
    }

    cdw[P::N1 - P::K..].copy_from_slice(msg);
}

/// Compute syndromes of a received word.
/// S_i = cdw(α^(i+1)) for i = 0..2*DELTA-1, evaluated via Horner.
pub(crate) fn compute_syndromes<P: Params>(cdw: &[u8]) -> SecretVec<u16> {
    let n_roots = 2 * P::DELTA;
    let mut syndromes = SecretVec::<u16>::new(n_roots);

    let mut omega = SecretVec::<u16>::new(n_roots);
    let mut cur = 2u16;
    for i in 0..n_roots {
        omega[i] = cur;
        cur = gf::gf_mul(cur, 2);
    }

    for i in 0..n_roots {
        let mut val = 0u16;
        for j in (0..P::N1).rev() {
            val = gf::gf_mul(val, omega[i]) ^ u16::from(cdw[j]);
        }
        syndromes[i] = val;
    }

    syndromes
}

/// Berlekamp-Massey algorithm: find error locator polynomial sigma from syndromes.
/// Returns (sigma, degree) — sigma coefficients and its degree.
/// (Constant-time version — all branches on secret data replaced with
/// `conditional_select` and arithmetic masking.)
pub(crate) fn berlekamp_massey<P: Params>(syndromes: &[u16]) -> (SecretVec<u16>, usize) {
    let mut sigma = SecretVec::<u16>::new(P::DELTA + 1);
    sigma[0] = 1;
    let mut sigma_copy = SecretVec::<u16>::new(P::DELTA + 1);
    let mut deg_sigma = 0usize;
    let mut deg_sigma_copy;
    let mut deg_sigma_p = 0usize;
    let mut x_sigma_p = SecretVec::<u16>::new(P::DELTA + 1);
    x_sigma_p[1] = 1;
    let mut pp: i64 = -1;
    let mut d_p = 1u16;
    let mut d = syndromes[0];

    for mu in 0..2 * P::DELTA {
        sigma_copy.copy_from_slice(&sigma);
        deg_sigma_copy = deg_sigma;

        // CT: dd = d * d_p^{-1}
        let dd = gf::gf_mul(d, gf::gf_inverse(d_p));

        for i in 1..=P::DELTA.min(mu + 1) {
            sigma[i] ^= gf::gf_mul(dd, x_sigma_p[i]);
        }

        // CT deg_x = (pp < 0) ? mu + 1 : mu - |pp|
        let pp_is_neg = Choice::from((((pp as u64) >> 63) as u8) & 1);
        let pp_abs = pp.unsigned_abs() as usize;
        let deg_x_nonneg = mu.wrapping_sub(pp_abs);
        let deg_x_neg = mu + 1;
        let deg_x = u64::conditional_select(&(deg_x_nonneg as u64), &(deg_x_neg as u64), pp_is_neg)
            as usize;
        let deg_x_sigma = deg_x + deg_sigma_p;

        // CT deg_increase = (d != 0) AND (deg_x_sigma > deg_sigma)
        let d_ne_zero = d.ct_ne(&0u16);
        let deg_gt = ct_gt_usize(deg_x_sigma, deg_sigma);
        let deg_increase = d_ne_zero & deg_gt;

        // CT deg_sigma = deg_increase ? deg_x_sigma.min(DELTA) : deg_sigma
        let new_deg_sigma = deg_x_sigma.min(P::DELTA);
        deg_sigma =
            u64::conditional_select(&(deg_sigma as u64), &(new_deg_sigma as u64), deg_increase)
                as usize;

        if mu == 2 * P::DELTA - 1 {
            break;
        }

        // CT update of pp, d_p, x_sigma_p, deg_sigma_p.
        let new_pp = i64::try_from(mu).expect("mu fits in i64");
        pp = i64::conditional_select(&pp, &new_pp, deg_increase);

        d_p = u16::conditional_select(&d_p, &d, deg_increase);

        for i in (1..=P::DELTA).rev() {
            x_sigma_p[i] =
                u16::conditional_select(&x_sigma_p[i - 1], &sigma_copy[i - 1], deg_increase);
        }
        x_sigma_p[0] = 0;

        deg_sigma_p = u64::conditional_select(
            &(deg_sigma_p as u64),
            &(deg_sigma_copy as u64),
            deg_increase,
        ) as usize;

        d = syndromes[mu + 1];
        for i in 1..=P::DELTA.min(mu + 1) {
            d ^= gf::gf_mul(sigma[i], syndromes[mu + 1 - i]);
        }
    }

    (sigma, deg_sigma)
}

/// Find roots of the error locator polynomial via Chien search.
/// Evaluates sigma at α^{-pos} for pos = 0..N1-1.
/// The error locator polynomial has form λ(x) = Π (1 - x·α^{pos_j}),
/// so λ(α^{-pos_j}) = 0. We evaluate σ(α^{-pos}) for each codeword position.
pub(crate) fn chien_search<P: Params>(sigma: &[u16]) -> SecretVec<bool> {
    let mut errors = SecretVec::<bool>::new(P::N1);
    let alpha_inv = gf::gf_inverse(2);
    let mut beta = 1u16;
    for pos in 0..P::N1 {
        let mut val = 0u16;
        for &coeff in sigma.iter().rev() {
            val = gf::gf_mul(val, beta) ^ coeff;
        }
        // Branchless root test (val is secret-derived).
        errors[pos] = u8::conditional_select(&0u8, &1u8, val.ct_eq(&0u16)) == 1;
        beta = gf::gf_mul(beta, alpha_inv);
    }
    errors
}

/// Compute z(x) for the Forney formula, matching the HQC reference:
/// z[0] = 1 and, for i >= 1, z[i] = sigma[i] ^ (sigma * S)[i-1], where
/// `S(x) = Σ_{i=0}^{2Δ-1} syndromes[i] * x^i`.
pub(crate) fn compute_z_poly<P: Params>(
    sigma: &[u16],
    degree: usize,
    syndromes: &[u16],
) -> SecretVec<u16> {
    let mut z = SecretVec::<u16>::new(P::DELTA + 1);
    z[0] = 1;

    // Fixed iteration bound (1..=DELTA) — `degree` is secret, so every z[i]
    // is computed fully and then masked to zero when i > degree
    // (bit-identical to the previous variable-length slice + loop).
    for i in 1..=P::DELTA {
        let mut zi = sigma[i];
        if i == 1 {
            zi ^= syndromes[0];
        } else {
            zi ^= syndromes[i - 1];
            for j in 1..i {
                zi ^= gf::gf_mul(sigma[j], syndromes[i - j - 1]);
            }
        }
        let in_degree = ct_gt_usize(degree, i - 1); // degree >= i
        z[i] = u16::conditional_select(&0u16, &zi, in_degree);
    }

    z
}

/// Compute error values using the Forney formula.
/// Ported from libQ's approach: map error values directly to error positions
/// found by Chien search, avoiding the beta-check loop.
pub(crate) fn compute_error_values<P: Params>(
    z: &[u16],
    error_positions: &[bool],
) -> SecretVec<u16> {
    let mut error_values = SecretVec::<u16>::new(P::N1);

    // Fully fixed-iteration, constant-time Forney. `pos` and `k` are public
    // loop counters, so `pow2[pos]`/`pow2[k]` are public-indexed;
    // the SECRET error_positions booleans only enter through
    // `conditional_select`. Error values at non-error positions are masked
    // to zero. Bit-identical to the previous variable-iteration form.
    let mut pow2 = alloc::vec![0u16; P::N1];
    let mut p = 1u16;
    for slot in pow2.iter_mut() {
        *slot = p;
        p = gf::gf_mul(p, 2);
    }

    for pos in 0..P::N1 {
        let beta = pow2[pos];
        let beta_inv = gf::gf_inverse(beta);

        // z(β^{-1}) = Σ_{j=0}^{δ} z[j] * β^{-j}; z[0] = 1.
        let mut tmp1 = 1u16;
        let mut inv_pow = 1u16;
        for j in 1..=P::DELTA.min(z.len() - 1) {
            inv_pow = gf::gf_mul(inv_pow, beta_inv);
            tmp1 ^= gf::gf_mul(inv_pow, z[j]);
        }

        // Π_{k≠pos, error_positions[k]} (1 + β^{-1}·β_k)
        let mut tmp2 = 1u16;
        for k in 0..P::N1 {
            if k == pos {
                continue;
            }
            let factor = 1u16 ^ gf::gf_mul(beta_inv, pow2[k]);
            let is_other_error = Choice::from(u8::from(error_positions[k]));
            tmp2 = u16::conditional_select(&tmp2, &gf::gf_mul(tmp2, factor), is_other_error);
        }

        let e = gf::gf_mul(tmp1, gf::gf_inverse(tmp2));
        let e = u16::conditional_select(&0u16, &e, Choice::from(u8::from(tmp2 != 0)));
        let e = u16::conditional_select(&0u16, &e, Choice::from(u8::from(error_positions[pos])));
        error_values[pos] = e;
    }

    error_values
}

/// Full Reed-Solomon decode pipeline: syndromes → Berlekamp-Massey → Chien
/// search → Forney (error values) → correct → extract last K bytes.
/// Returns the decoded message (K bytes) in a zeroizing wrapper.
pub(crate) fn decode<P: Params>(cdw: &mut [u8]) -> SecretVec<u8> {
    let syndromes = compute_syndromes::<P>(cdw);

    let (sigma, degree) = berlekamp_massey::<P>(&syndromes);

    let error_positions = chien_search::<P>(&sigma);

    let z = compute_z_poly::<P>(&sigma, degree, &syndromes);

    let error_values = compute_error_values::<P>(&z, &error_positions);

    // Constant-time correction gate: `degree > DELTA` was a secret-dependent
    // early return; the correction is now masked to zero instead
    // (sigma.len() is always DELTA+1, so the old second clause never fired).
    let apply = ct_gt_usize(P::DELTA + 1, degree); // degree <= DELTA
    for i in 0..cdw.len() {
        let ev = u16::conditional_select(&0u16, &error_values[i], apply);
        cdw[i] ^= (ev & 0xFF) as u8;
    }

    let mut msg = SecretVec::<u8>::new(P::K);
    msg.copy_from_slice(&cdw[P::N1 - P::K..]);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Hqc128;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn test_rs_encode_sizes() {
        let mut cdw = vec![0u8; <Hqc128 as Params>::N1];
        let msg = vec![0xABu8; <Hqc128 as Params>::K];
        encode::<Hqc128>(&mut cdw, &msg);
        assert_eq!(&cdw[<Hqc128 as Params>::N1 - <Hqc128 as Params>::K..], &msg);
    }

    #[test]
    fn test_rs_encode_nonzero() {
        let mut cdw = vec![0u8; <Hqc128 as Params>::N1];
        let msg = vec![0x42u8; <Hqc128 as Params>::K];
        encode::<Hqc128>(&mut cdw, &msg);
        assert!(cdw.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_rs_syndrome_zero_codeword() {
        let cdw = vec![0u8; <Hqc128 as Params>::N1];
        let syndromes = compute_syndromes::<Hqc128>(&cdw);
        assert!(syndromes.iter().all(|&s| s == 0));
    }

    #[test]
    fn test_rs_syndrome_roundtrip() {
        let mut cdw = vec![0u8; <Hqc128 as Params>::N1];
        let msg = vec![0xABu8; <Hqc128 as Params>::K];
        encode::<Hqc128>(&mut cdw, &msg);
        let syndromes = compute_syndromes::<Hqc128>(&cdw);
        assert!(
            syndromes.iter().all(|&s| s == 0),
            "Valid codeword should have all-zero syndromes (or syndrome computation needs adjustment)"
        );
    }

    #[test]
    fn test_rs_decode_no_errors() {
        let mut cdw = vec![0u8; <Hqc128 as Params>::N1];
        let msg = vec![0xAB; <Hqc128 as Params>::K];
        encode::<Hqc128>(&mut cdw, &msg);
        let decoded = decode::<Hqc128>(&mut cdw);
        assert_eq!(
            *decoded, msg,
            "No-error decode should recover original message"
        );
    }

    #[test]
    fn test_rs_decode_single_error() {
        let mut cdw = vec![0u8; <Hqc128 as Params>::N1];
        let msg = vec![0x42; <Hqc128 as Params>::K];
        encode::<Hqc128>(&mut cdw, &msg);

        cdw[5] ^= 0xFF;

        let decoded = decode::<Hqc128>(&mut cdw);
        assert_eq!(*decoded, msg, "Should correct single byte error");
    }

    #[test]
    fn test_rs_decode_delta_errors() {
        let mut cdw = vec![0u8; <Hqc128 as Params>::N1];
        let msg = vec![0xAB; <Hqc128 as Params>::K];
        encode::<Hqc128>(&mut cdw, &msg);

        let delta = <Hqc128 as Params>::DELTA;
        for i in 0..delta {
            cdw[i] ^= 0x55 + i as u8;
        }

        let decoded = decode::<Hqc128>(&mut cdw);
        assert_eq!(*decoded, msg, "Should correct up to DELTA errors");
    }

    #[test]
    fn test_rs_berlekamp_massey() {
        let mut cdw = vec![0u8; <Hqc128 as Params>::N1];
        let msg = vec![0x42; <Hqc128 as Params>::K];
        encode::<Hqc128>(&mut cdw, &msg);

        cdw[10] ^= 0xFF;

        let syndromes = compute_syndromes::<Hqc128>(&cdw);
        let (sigma, degree) = berlekamp_massey::<Hqc128>(&syndromes);

        assert_eq!(degree, 1, "Single error → degree 1 sigma");
        let errors = chien_search::<Hqc128>(&sigma);
        let _num_errs = errors.iter().filter(|&&e| e).count();
        let _err_positions: Vec<usize> = errors
            .iter()
            .enumerate()
            .filter(|&(_, &e)| e)
            .map(|(i, _)| i)
            .collect();
        assert!(errors[10], "Should detect error at position 10");
        assert_eq!(
            errors.iter().filter(|&&e| e).count(),
            1,
            "Should find exactly 1 error"
        );
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
    use crate::params::Hqc128;
    use alloc::vec;
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

    /// End-to-end RS decode pipeline. Class A = valid codeword pool
    /// (light path), class B = random received word pool (full variable-time
    /// Berlekamp-Massey + Chien + Forney).
    #[test]
    fn probe_rs_decode() {
        if !enabled() {
            eprintln!("[CT-VALIDATE] hqc RS probe skipped (set CT_VALIDATE=1)");
            return;
        }
        const N: usize = 256;
        let fixed: Vec<Vec<u8>> = core::hint::black_box(
            (0..N)
                .map(|_| {
                    let mut c = vec![0u8; <Hqc128 as Params>::N1];
                    encode::<Hqc128>(&mut c, &[0xABu8; <Hqc128 as Params>::K]);
                    c
                })
                .collect(),
        );
        let mut rng = XorShift::new();
        let random: Vec<Vec<u8>> = core::hint::black_box(
            (0..N)
                .map(|_| {
                    (0..<Hqc128 as Params>::N1)
                        .map(|_| (rng.next_u64() & 0xFF) as u8)
                        .collect()
                })
                .collect(),
        );
        let mut ca = 0usize;
        let a = measure(1200, 50, || {
            let mut buf = fixed[ca & (N - 1)].clone();
            ca += 1;
            let m = decode::<Hqc128>(&mut buf);
            u64::from(m[0])
        });
        let mut cb = 0usize;
        let b = measure(1200, 50, || {
            let mut buf = random[cb & (N - 1)].clone();
            cb += 1;
            let m = decode::<Hqc128>(&mut buf);
            u64::from(m[0])
        });
        let t = report("hqc RS decode pipeline", &a, &b);
        let _ = t;
    }
}
