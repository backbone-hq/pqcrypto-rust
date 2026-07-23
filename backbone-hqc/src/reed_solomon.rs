//! Reed-Solomon code over GF(2⁸): systematic encoder and syndrome-based decoder.
//! The RS code has parameters (n1 = 2^M - 1 - (G - 1), k = K) correcting up to DELTA errors.
//! Decoder uses: Berlekamp-Massey (error locator polynomial), Chien search (root finding),
//! Forney formula (error values).

use crate::gf;
use crate::params::Params;
use alloc::vec;
use alloc::vec::Vec;
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
pub(crate) fn chien_search<P: Params>(sigma: &[u16]) -> Vec<bool> {
    let mut errors = vec![false; P::N1];
    let alpha_inv = gf::gf_inverse(2);
    let mut beta = 1u16;
    for pos in 0..P::N1 {
        let mut val = 0u16;
        for &coeff in sigma.iter().rev() {
            val = gf::gf_mul(val, beta) ^ coeff;
        }
        if val == 0 {
            errors[pos] = true;
        }
        beta = gf::gf_mul(beta, alpha_inv);
    }
    errors
}

/// Compute z(x) for the Forney formula: z(x) = sigma(x) * (1 + S(x)) mod x^{DELTA+1}.
/// Where `S(x) = Σ_{i=0}^{2Δ-1} S_{i+1} * x^i = Σ_{i=0}^{2Δ-1} syndromes[i] * x^i`.
pub(crate) fn compute_z_poly<P: Params>(
    sigma: &[u16],
    degree: usize,
    syndromes: &[u16],
) -> SecretVec<u16> {
    let mut z = SecretVec::<u16>::new(P::DELTA + 1);
    z[0] = 1;

    z[1..=P::DELTA.min(degree)].copy_from_slice(&sigma[1..=P::DELTA.min(degree)]);

    if P::DELTA >= 1 {
        z[1] ^= syndromes[0];
    }

    for i in 2..=P::DELTA.min(degree) {
        z[i] ^= syndromes[i - 1];
        for j in 1..i {
            z[i] ^= gf::gf_mul(sigma[j], syndromes[i - j - 1]);
        }
    }

    z
}

/// Compute error values using the Forney formula.
/// For each error position `p` (where `error[p]` is true):
///   β_j = α^{-pos_j} is the error locator for position pos_j.
///   e_j = z(α^{pos_j}) / λ'(α^{pos_j}) = z(β_j^{-1}) / Π_{k≠j} (1 - β_j^{-1}·β_k)
pub(crate) fn compute_error_values<P: Params>(
    z: &[u16],
    error_positions: &[bool],
) -> SecretVec<u16> {
    let mut error_values = SecretVec::<u16>::new(P::N1);

    let num_errors = error_positions.iter().filter(|&&e| e).count();
    if num_errors == 0 {
        return error_values;
    }
    if num_errors > P::DELTA {
        return error_values;
    }

    let alpha_inv = gf::gf_inverse(2);
    let mut betas = SecretVec::<u16>::new(num_errors);
    let mut beta = 1u16;
    let mut idx = 0;
    for pos in 0..P::N1 {
        if error_positions[pos] {
            betas[idx] = beta;
            idx += 1;
        }
        beta = gf::gf_mul(beta, alpha_inv);
    }

    for (i, &beta_i) in betas.iter().enumerate() {
        let beta_i_inv = gf::gf_inverse(beta_i);

        let mut tmp1 = 1u16;
        let mut inv_pow = 1u16;
        for j in 1..=P::DELTA.min(z.len() - 1) {
            inv_pow = gf::gf_mul(inv_pow, beta_i_inv);
            tmp1 ^= gf::gf_mul(inv_pow, z[j]);
        }

        let mut tmp2 = 1u16;
        for (k, &beta_k) in betas.iter().enumerate() {
            if k != i {
                tmp2 = gf::gf_mul(tmp2, 1 ^ gf::gf_mul(beta_i_inv, beta_k));
            }
        }

        let e_val = if tmp2 != 0 {
            gf::gf_mul(tmp1, gf::gf_inverse(tmp2))
        } else {
            0
        };

        let alpha_inv2 = gf::gf_inverse(2);
        let mut beta_check = 1u16;
        for pos in 0..P::N1 {
            if error_positions[pos] && beta_check == beta_i {
                error_values[pos] = e_val;
                break;
            }
            beta_check = gf::gf_mul(beta_check, alpha_inv2);
        }
    }

    error_values
}

/// Correct a codeword by XORing error values at error positions.
pub(crate) fn correct_errors(cdw: &mut [u8], error_values: &[u16]) {
    for i in 0..cdw.len() {
        // error_values[i] is GF(2⁸) value < 256; mask makes truncation explicit
        cdw[i] ^= (error_values[i] & 0xFF) as u8;
    }
}

/// Full Reed-Solomon decode pipeline.
/// 1. Compute syndromes
/// 2. Berlekamp-Massey → error locator polynomial sigma
/// 3. Chien search → error positions
/// 4. Compute z-poly → Forney numerator
/// 5. Compute error values → Forney formula
/// 6. Correct errors in codeword
/// 7. Extract message from last K bytes
///
/// Returns the decoded message (K bytes) in a zeroizing wrapper.
pub(crate) fn decode<P: Params>(cdw: &mut [u8]) -> SecretVec<u8> {
    let syndromes = compute_syndromes::<P>(cdw);

    let (sigma, degree) = berlekamp_massey::<P>(&syndromes);

    if degree > P::DELTA || sigma.len() > P::DELTA + 1 {
        let mut msg = SecretVec::<u8>::new(P::K);
        msg.copy_from_slice(&cdw[P::N1 - P::K..]);
        return msg;
    }

    let error_positions = chien_search::<P>(&sigma);

    let z = compute_z_poly::<P>(&sigma, degree, &syndromes);

    let error_values = compute_error_values::<P>(&z, &error_positions);

    correct_errors(cdw, &error_values);

    let mut msg = SecretVec::<u8>::new(P::K);
    msg.copy_from_slice(&cdw[P::N1 - P::K..]);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Hqc128;

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
