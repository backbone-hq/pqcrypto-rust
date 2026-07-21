//! ML-DSA (FIPS 204) signing operations: key generation, signing, and verification.

use crate::error::Error;
use crate::field::Q;
use crate::matrix::expand_matrix;
use crate::ntt::{inv_ntt, ntt, ntt_mul};
use crate::params::Params;
use crate::poly::Poly;
use crate::sampling::{sample_poly_challenge, sample_poly_eta, sample_poly_gamma1};
use alloc::vec;
use alloc::vec::Vec;
use backbone_pqcrypto_internals::ct::{ct_le_i32, ct_lt_i32};
use backbone_pqcrypto_internals::secret::SecretArray;
use sha3::{digest::ExtendableOutput, digest::Update, digest::XofReader, Shake256};
use subtle::{Choice, ConditionallySelectable};

/// Maximum rejection-sampling iterations. Set to cover the practical worst case
/// across all parameter sets. Each iteration always runs to completion to
/// eliminate timing variation from early-exit paths.
/// Probability of exhaustion: ~0.5^64 < 10^-19 for all parameter sets.
const MAX_ATTEMPTS: usize = 64;

#[must_use]
pub(crate) fn hash_tr_msg_with_prefix(tr: &[u8], prefix: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut shake = Shake256::default();
    shake.update(tr);
    shake.update(prefix);
    shake.update(msg);
    let mut reader = shake.finalize_xof();
    reader.read(&mut out);
    out
}

pub(crate) fn domain_prefix(ctx: &[u8], prehash: Option<(&[u8], &[u8])>) -> Result<Vec<u8>, Error> {
    if ctx.len() > 255 {
        return Err(Error::InvalidContextLength);
    }

    let mut prefix = Vec::with_capacity(
        2 + ctx.len()
            + prehash
                .map(|(oid, ph)| oid.len() + ph.len())
                .unwrap_or_default(),
    );
    prefix.push(if prehash.is_some() { 1 } else { 0 });
    prefix.push(u8::try_from(ctx.len()).expect("ctx length is <= 255"));
    prefix.extend_from_slice(ctx);
    if let Some((oid, ph)) = prehash {
        prefix.extend_from_slice(oid);
        prefix.extend_from_slice(ph);
    }
    Ok(prefix)
}

fn sample_in_ball(c_tilde: &[u8; 32], tau: usize) -> Poly {
    let mut c = Poly::new();
    sample_poly_challenge(&mut c, c_tilde, tau);
    c
}

fn pack_bits(buf: &mut [u8], data: &[i32], bits: usize, mut bit_pos: usize) -> usize {
    for &val in data {
        let val = u32::from_ne_bytes(val.to_ne_bytes()) & ((1u32 << bits) - 1);
        for i in 0..bits {
            if (val >> i) & 1 != 0 {
                buf[bit_pos / 8] |= 1 << (bit_pos % 8);
            }
            bit_pos += 1;
        }
    }
    bit_pos
}

fn unpack_bits(buf: &[u8], data: &mut [i32], bits: usize, mut bit_pos: usize) -> usize {
    for coeff in data {
        let mut val = 0u32;
        for i in 0..bits {
            if (buf[bit_pos / 8] >> (bit_pos % 8)) & 1 != 0 {
                val |= 1 << i;
            }
            bit_pos += 1;
        }
        // SAFETY: val is masked to `bits` bits, and encodes a coefficient offset
        // that will be subtracted below. This is intentional modular arithmetic.
        *coeff = i32::try_from(val).expect("value fits in i32");
    }
    bit_pos
}

fn matrix_multiply<P: Params>(a: &[Vec<Poly>], y_ntt: &[Poly]) -> Vec<Poly> {
    let mut w = vec![Poly::new(); P::K];
    for i in 0..P::K {
        for j in 0..P::L {
            let mut prod = Poly::new();
            ntt_mul(&a[i][j], &y_ntt[j], &mut prod);
            w[i].add(&prod);
        }
    }
    w
}

#[must_use]
pub(crate) fn keygen<P: Params>(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut shake = Shake256::default();
    shake.update(seed);
    // FIPS 204 Section 5.1: (ρ, ρ′, K) = H(seed || byte(K) || byte(L))
    shake.update(&[
        u8::try_from(P::K).expect("P::K fits in u8"),
        u8::try_from(P::L).expect("P::L fits in u8"),
    ]);
    let mut reader = shake.finalize_xof();

    let mut rho = [0u8; 32];
    reader.read(&mut rho);
    let mut rho_prime = [0u8; 64];
    reader.read(&mut rho_prime);
    let mut k = [0u8; 32];
    reader.read(&mut k);

    let mut a = vec![vec![Poly::new(); P::L]; P::K];
    expand_matrix::<P>(&mut a, &rho);

    let eta = P::ETA;
    let mut s1 = vec![Poly::new(); P::L];
    let mut s2 = vec![Poly::new(); P::K];
    for i in 0..P::L {
        sample_poly_eta(
            &mut s1[i],
            &rho_prime,
            u16::try_from(i).expect("i < P::L fits in u16"),
            eta,
        );
    }
    for i in 0..P::K {
        sample_poly_eta(
            &mut s2[i],
            &rho_prime,
            u16::try_from(P::L + i).expect("P::L + i fits in u16"),
            eta,
        );
    }

    let mut s1_ntt = s1.clone();
    for si in s1_ntt.iter_mut() {
        ntt(si);
    }

    for row in a.iter_mut() {
        for val in row.iter_mut() {
            ntt(val);
        }
    }

    let mut t = vec![Poly::new(); P::K];
    for i in 0..P::K {
        // First term: store directly (raw)
        {
            let mut prod = Poly::new();
            ntt_mul(&a[i][0], &s1_ntt[0], &mut prod);
            t[i] = prod;
        }
        // Remaining terms: raw accumulate, no per-term reduction
        for j in 1..P::L {
            let mut prod = Poly::new();
            ntt_mul(&a[i][j], &s1_ntt[j], &mut prod);
            t[i].add(&prod);
        }
        // Reduce once before inv_ntt (matching C ref)
        for coeff in t[i].coeffs.iter_mut() {
            *coeff = crate::field::reduce32(*coeff);
        }
        inv_ntt(&mut t[i]);
        // Add s2 in time domain, raw, then reduce
        for j in 0..256 {
            t[i].coeffs[j] += s2[i].coeffs[j];
        }
        for coeff in t[i].coeffs.iter_mut() {
            *coeff = crate::field::reduce32(*coeff);
            *coeff = crate::field::caddq(*coeff);
        }
    }

    let d = i32::try_from(P::D).expect("P::D fits in i32");
    let mut t0 = vec![Poly::new(); P::K];
    let mut t1 = vec![Poly::new(); P::K];
    for i in 0..P::K {
        for j in 0..256 {
            let (r1, r0) = Poly::power2round(t[i].coeffs[j], d);
            t1[i].coeffs[j] = r1;
            t0[i].coeffs[j] = r0;
        }
    }

    // Encode t1 (10 bits per coefficient) and compute tr = H(rho || t1)
    let pk_bits = 10usize;
    let t1_bytes = (P::K * 256 * pk_bits).div_ceil(8);
    let mut pk = vec![0u8; 32 + t1_bytes];
    pk[..32].copy_from_slice(&rho);

    let mut bit_pos = 32 * 8;
    for poly in &t1 {
        bit_pos = pack_bits(&mut pk, &*poly.coeffs, pk_bits, bit_pos);
    }

    // tr = H(rho || t1_enc)
    let mut tr = [0u8; 64];
    {
        let mut shake = Shake256::default();
        shake.update(&pk[..32 + t1_bytes]);
        let mut tr_reader = shake.finalize_xof();
        tr_reader.read(&mut tr);
    }

    // Encode secret key: rho || K || tr || s1 || s2 || t0
    let eta_bits = (eta * 2 + 1).ilog2() as usize + 1;
    let s1_bytes = (P::L * 256 * eta_bits).div_ceil(8);
    let s2_bytes = (P::K * 256 * eta_bits).div_ceil(8);
    let t0_bits = 13usize;
    let t0_bytes = (P::K * 256 * t0_bits).div_ceil(8);

    let mut sk = vec![0u8; 32 + 32 + 64 + s1_bytes + s2_bytes + t0_bytes];
    sk[..32].copy_from_slice(&rho);
    sk[32..64].copy_from_slice(&k);
    sk[64..128].copy_from_slice(&tr);

    let mut bit_pos = 128 * 8;
    // Encode s1 (eta bits)
    bit_pos = encode_single_poly_eta(&s1[0], &mut sk, bit_pos, eta);
    for poly in &s1[1..] {
        bit_pos = encode_single_poly_eta(poly, &mut sk, bit_pos, eta);
    }
    // Encode s2 (eta bits)
    for poly in &s2 {
        bit_pos = encode_single_poly_eta(poly, &mut sk, bit_pos, eta);
    }
    // Encode t0 (13 bits)
    for poly in &t0 {
        bit_pos = encode_single_poly_t0(poly, &mut sk, bit_pos, 13);
    }

    (pk, sk)
}

fn encode_single_poly_eta(poly: &Poly, buf: &mut [u8], bit_offset: usize, eta: usize) -> usize {
    let bits = (eta * 2 + 1).ilog2() as usize + 1;
    let mut bit_pos = bit_offset;
    for &coeff in poly.coeffs.iter() {
        let eta_i32 = i32::try_from(eta).expect("eta fits in i32");
        let val = u32::from_ne_bytes((coeff + eta_i32).to_ne_bytes()) & ((1u32 << bits) - 1);
        let byte_idx = bit_pos / 8;
        let bit_off = bit_pos % 8;
        buf[byte_idx] |= (u8::try_from(val).expect("value fits in u8")) << bit_off;
        if bit_off + bits > 8 {
            buf[byte_idx + 1] |= u8::try_from(val >> (8 - bit_off)).expect("value fits in u8");
        }
        if bit_off + bits > 16 {
            buf[byte_idx + 2] |= u8::try_from(val >> (16 - bit_off)).expect("value fits in u8");
        }
        bit_pos += bits;
    }
    bit_pos
}

fn encode_single_poly_t0(poly: &Poly, buf: &mut [u8], bit_offset: usize, bits: usize) -> usize {
    let mut bit_pos = bit_offset;
    for &coeff in poly.coeffs.iter() {
        // t0 is stored as centered remainder; encode as unsigned
        let val = (coeff % (1 << bits) + (1 << bits)) % (1 << bits);
        let byte_idx = bit_pos / 8;
        let bit_off = bit_pos % 8;
        buf[byte_idx] |= (u8::try_from(val & 0xFF).expect("masked value fits in u8")) << bit_off;
        if bit_off + bits > 8 {
            buf[byte_idx + 1] |=
                u8::try_from((val >> (8 - bit_off)) & 0xFF).expect("masked value fits in u8");
        }
        if bit_off + bits > 16 {
            buf[byte_idx + 2] |=
                u8::try_from((val >> (16 - bit_off)) & 0xFF).expect("masked value fits in u8");
        }
        bit_pos += bits;
    }
    bit_pos
}

fn decode_poly_from_bits(
    buf: &[u8],
    bit_offset: usize,
    num_coeffs: usize,
    bits: usize,
    offset: i32,
) -> Poly {
    let mut poly = Poly::new();
    let mut bit_pos = bit_offset;
    for coeff in poly.coeffs.iter_mut().take(num_coeffs) {
        let byte_idx = bit_pos / 8;
        let bit_off = bit_pos % 8;
        let mut val = u32::from(buf[byte_idx]) >> bit_off;
        if bit_off + bits > 8 {
            val |= u32::from(buf[byte_idx + 1]) << (8 - bit_off);
        }
        if bit_off + bits > 16 {
            val |= u32::from(buf[byte_idx + 2]) << (16 - bit_off);
        }
        if bit_off + bits > 24 {
            val |= u32::from(buf[byte_idx + 3]) << (24 - bit_off);
        }
        val &= (1u32 << bits) - 1;
        *coeff = i32::try_from(val).expect("value fits in i32") - offset;
        bit_pos += bits;
    }
    poly
}

fn decode_poly_t0_from_bits(buf: &[u8], bit_offset: usize, bits: usize) -> Poly {
    let mut poly = Poly::new();
    let mut bit_pos = bit_offset;
    for coeff in poly.coeffs.iter_mut() {
        let byte_idx = bit_pos / 8;
        let bit_off = bit_pos % 8;
        let mut val = u32::from(buf[byte_idx] >> bit_off);
        if bit_off + bits > 8 {
            val |= u32::from(buf[byte_idx + 1]) << (8 - bit_off);
        }
        if bit_off + bits > 16 {
            val |= u32::from(buf[byte_idx + 2]) << (16 - bit_off);
        }
        val &= (1u32 << bits) - 1;
        // Convert from unsigned to centered representation:
        // if val >= 2^(bits-1), then val - 2^bits (i.e., centered)
        *coeff = i32::try_from(val).expect("value fits in i32")
            - (if val > (1u32 << (bits - 1)) {
                1 << bits
            } else {
                0
            });
        bit_pos += bits;
    }
    poly
}

fn encode_w1_high_bits<P: Params>(w1: &[Poly]) -> Vec<u8> {
    let w1_bits = P::W1_BITS;
    let w1_bytes = (P::K * 256 * w1_bits).div_ceil(8);
    let mut buf = vec![0u8; w1_bytes];
    let mut bit_pos = 0;
    for poly in w1 {
        for &coeff in poly.coeffs.iter() {
            let val = u32::from_ne_bytes(coeff.to_ne_bytes()) & ((1u32 << w1_bits) - 1);
            let bits = w1_bits;
            let byte_idx = bit_pos / 8;
            let bit_off = bit_pos % 8;
            buf[byte_idx] |= (u8::try_from(val).expect("value fits in u8")) << bit_off;
            if bit_off + bits > 8 {
                buf[byte_idx + 1] |= u8::try_from(val >> (8 - bit_off)).expect("value fits in u8");
            }
            if bit_off + bits > 16 {
                buf[byte_idx + 2] |= u8::try_from(val >> (16 - bit_off)).expect("value fits in u8");
            }
            bit_pos += bits;
        }
    }
    buf
}

fn encode_hint<P: Params>(h: &[Poly]) -> Vec<u8> {
    let omega = P::OMEGA;
    let k = P::K;
    let mut buf = vec![0u8; omega + k];
    let mut index = 0usize;
    for (i, poly) in h.iter().enumerate() {
        for (j, &coeff) in poly.coeffs.iter().enumerate() {
            if coeff != 0 {
                if index >= omega {
                    return buf;
                }
                buf[index] = u8::try_from(j).expect("value fits in u8");
                index += 1;
            }
        }
        buf[omega + i] = u8::try_from(index).expect("value fits in u8");
    }
    buf
}

fn challenge_multiply(c: &Poly, v_ntt: &[Poly]) -> Vec<Poly> {
    let mut c_ntt = c.clone();
    ntt(&mut c_ntt);
    let mut result = Vec::with_capacity(v_ntt.len());
    for vi in v_ntt {
        let mut prod = Poly::new();
        ntt_mul(&c_ntt, vi, &mut prod);
        inv_ntt(&mut prod);
        for coeff in prod.coeffs.iter_mut() {
            *coeff = crate::field::reduce32(*coeff);
        }
        result.push(prod);
    }
    result
}

fn decompose_vec(w: &[Poly], gamma2: i32) -> (Vec<Poly>, Vec<Poly>) {
    let mut w1 = vec![Poly::new(); w.len()];
    let mut w0 = vec![Poly::new(); w.len()];
    for i in 0..w.len() {
        for j in 0..256 {
            let (hi, lo) = Poly::decompose(w[i].coeffs[j], gamma2 * 2);
            w1[i].coeffs[j] = hi;
            w0[i].coeffs[j] = lo;
        }
    }
    (w1, w0)
}

/// Decode the secret key vectors s₁, s₂, t₀ from the serialized secret key.
fn decode_signing_key<P: Params>(sk: &[u8]) -> (Vec<Poly>, Vec<Poly>, Vec<Poly>) {
    let eta = P::ETA;
    let eta_bits = (eta * 2 + 1).ilog2() as usize + 1;
    let t0_bits = 13usize;

    let s1_start_bits = 128 * 8;
    let mut s1 = Vec::with_capacity(P::L);
    let mut bit_pos = s1_start_bits;
    for _ in 0..P::L {
        let eta_i32 = i32::try_from(eta).expect("eta fits in i32");
        let poly = decode_poly_from_bits(sk, bit_pos, 256, eta_bits, eta_i32);
        bit_pos += 256 * eta_bits;
        s1.push(poly);
    }

    let mut s2 = Vec::with_capacity(P::K);
    for _ in 0..P::K {
        let eta_i32 = i32::try_from(eta).expect("eta fits in i32");
        let poly = decode_poly_from_bits(sk, bit_pos, 256, eta_bits, eta_i32);
        bit_pos += 256 * eta_bits;
        s2.push(poly);
    }

    let mut t0 = Vec::with_capacity(P::K);
    for _ in 0..P::K {
        let poly = decode_poly_t0_from_bits(sk, bit_pos, t0_bits);
        bit_pos += 256 * t0_bits;
        t0.push(poly);
    }

    (s1, s2, t0)
}

/// Prepare NTT-domain signing matrices: NTT(s₁), NTT(s₂), NTT(t₀), expand A, NTT(A).
fn prepare_signing_matrices<P: Params>(
    s1: &[Poly],
    s2: &[Poly],
    t0: &[Poly],
    rho: &[u8],
) -> (Vec<Poly>, Vec<Poly>, Vec<Poly>, Vec<Vec<Poly>>) {
    let mut s1_ntt = s1.to_vec();
    for si in s1_ntt.iter_mut() {
        ntt(si);
    }

    let mut s2_ntt = s2.to_vec();
    for si in s2_ntt.iter_mut() {
        ntt(si);
    }

    let mut t0_ntt = t0.to_vec();
    for ti in t0_ntt.iter_mut() {
        ntt(ti);
    }

    let mut a = vec![vec![Poly::new(); P::L]; P::K];
    expand_matrix::<P>(&mut a, rho);
    for row in a.iter_mut() {
        for val in row.iter_mut() {
            ntt(val);
        }
    }

    (s1_ntt, s2_ntt, t0_ntt, a)
}

/// Compute the message digests: μ = CRH(tr || msg) and ρ′ = H(k || 0³² || μ).
fn compute_message_expansion(
    k: &[u8],
    tr: &[u8],
    prefix: &[u8],
    msg: &[u8],
    rnd: &[u8; 32],
) -> ([u8; 64], SecretArray<u8, 64>) {
    let mu = hash_tr_msg_with_prefix(tr, prefix, msg);

    // FIPS 204 §5.4.3: rhoprime = H(k || rnd || mu).
    let mut rhoprime = SecretArray::<u8, 64>::new();
    {
        let mut shake = Shake256::default();
        shake.update(k);
        shake.update(rnd);
        shake.update(&mu);
        let mut k_reader = shake.finalize_xof();
        k_reader.read(&mut *rhoprime);
    }

    (mu, rhoprime)
}

/// Sample the mask vector y ← Sample_γ₁(r′, nonce) for each polynomial.
fn sample_mask_y(y: &mut [Poly], rhoprime: &[u8; 64], nonce: &mut u16, gamma1: usize) {
    for yi in y.iter_mut() {
        sample_poly_gamma1(yi, rhoprime, *nonce, gamma1);
        *nonce = nonce.wrapping_add(1);
    }
}

/// Compute w = A·y (time domain), then decompose into (w₁, w₀).
fn compute_w_and_decompose<P: Params>(
    a: &[Vec<Poly>],
    y: &[Poly],
    gamma2: i32,
) -> (Vec<Poly>, Vec<Poly>, Vec<Poly>) {
    let mut y_ntt = y.to_vec();
    for yi in y_ntt.iter_mut() {
        ntt(yi);
    }
    let mut w = matrix_multiply::<P>(a, &y_ntt);
    for wi in w.iter_mut() {
        for coeff in wi.coeffs.iter_mut() {
            *coeff = crate::field::reduce32(*coeff);
        }
        inv_ntt(wi);
        for coeff in wi.coeffs.iter_mut() {
            *coeff = crate::field::caddq(*coeff);
        }
    }

    let (w1, w0) = decompose_vec(&w, gamma2);
    (w, w1, w0)
}

/// Encode w₁, compute c̃ = H(μ || w₁_enc), and derive c = SampleInBall(c̃).
fn compute_challenge<P: Params>(mu: &[u8; 64], w1: &[Poly], tau: usize) -> ([u8; 32], Poly) {
    let w1_enc = encode_w1_high_bits::<P>(w1);

    // c̃ = H(mu || w1)
    let mut c_tilde_seed = [0u8; 32];
    {
        let mut shake = Shake256::default();
        shake.update(mu);
        shake.update(&w1_enc);
        let mut c_reader = shake.finalize_xof();
        c_reader.read(&mut c_tilde_seed);
    }

    // c = SampleInBall(c̃)
    let c = sample_in_ball(&c_tilde_seed, tau);
    (c_tilde_seed, c)
}

/// Context for the response computation phase of signing.
struct SignResponseCtx<'a> {
    c: &'a Poly,
    c_tilde_seed: &'a [u8; 32],
    s1_ntt: &'a [Poly],
    s2_ntt: &'a [Poly],
    t0_ntt: &'a [Poly],
    y: &'a [Poly],
    w0: &'a [Poly],
    gamma1: i32,
    gamma2: i32,
    beta: i32,
}

/// Runs to completion (no early returns) to eliminate timing variation.
fn try_sign_response_ct<P: Params>(ctx: &SignResponseCtx) -> (Vec<u8>, Choice) {
    let cs1 = challenge_multiply(ctx.c, ctx.s1_ntt);
    let mut z = ctx.y.to_vec();
    for i in 0..P::L {
        z[i].add(&cs1[i]);
    }
    // CT norm check: branching would leak secret key structure.
    let z_max = z.iter().fold(0i32, |acc, zi| {
        let norm = zi.infinity_norm();
        let mask = (acc.wrapping_sub(norm)) >> 31;
        acc ^ (mask & (acc ^ norm))
    });
    let z_valid = ct_lt_i32(z_max, ctx.gamma1 - ctx.beta);

    let cs2 = challenge_multiply(ctx.c, ctx.s2_ntt);
    let mut r0 = ctx.w0.to_vec();
    for i in 0..P::K {
        r0[i].sub(&cs2[i]);
    }

    let r0_max = r0.iter().fold(0i32, |acc, ri| {
        let norm = ri.infinity_norm();
        let mask = (acc.wrapping_sub(norm)) >> 31;
        acc ^ (mask & (acc ^ norm))
    });
    let r0_valid = ct_lt_i32(r0_max, ctx.gamma2 - ctx.beta);

    let ct0 = challenge_multiply(ctx.c, ctx.t0_ntt);
    let ct0_max = ct0.iter().fold(0i32, |acc, ci| {
        let norm = ci.infinity_norm();
        let mask = (acc.wrapping_sub(norm)) >> 31;
        acc ^ (mask & (acc ^ norm))
    });
    let ct0_valid = ct_lt_i32(ct0_max, ctx.gamma2);

    let mut hint_w0 = ctx.w0.to_vec();
    for i in 0..P::K {
        hint_w0[i].sub(&cs2[i]);
    }
    for i in 0..P::K {
        for j in 0..256 {
            hint_w0[i].coeffs[j] += ct0[i].coeffs[j];
        }
    }
    let mut h = vec![Poly::new(); P::K];
    for i in 0..P::K {
        for j in 0..256 {
            let a0 = hint_w0[i].coeffs[j];
            // CT hint decision: a0 is secret-derived.
            // Original condition: a0 >= gamma2 || a0 < -gamma2.
            // Using gamma2 (not gamma2+1) for >=, matching the original.
            let ge_flag = !(a0.wrapping_sub(ctx.gamma2) >> 31);
            let lt_flag = a0.wrapping_add(ctx.gamma2) >> 31;
            let hint_choice = Choice::from(((ge_flag | lt_flag) as u8) & 1);
            h[i].coeffs[j] = i32::conditional_select(&0i32, &1i32, hint_choice);
        }
    }

    // CT hint weight: branching would leak aggregate information about `t₀`.
    let mut hint_count = 0usize;
    for hi in &h {
        for &hij in hi.coeffs.iter() {
            hint_count = hint_count.wrapping_add(hij as usize);
        }
    }
    let hint_valid = ct_le_i32(hint_count as i32, P::OMEGA as i32);

    // CT combine: old branch on secret-derived booleans.
    let valid = z_valid & r0_valid & ct0_valid & hint_valid;

    // Runs to completion regardless of validity to avoid timing variation.
    let gamma1_bits = if ctx.gamma1 == (1 << 17) { 18 } else { 20 };
    let z_bytes = (P::L * 256 * gamma1_bits).div_ceil(8);
    let h_bytes = P::OMEGA + P::K;
    let sig_len = 32 + z_bytes + h_bytes;
    let mut sig = vec![0u8; sig_len];
    sig[..32].copy_from_slice(ctx.c_tilde_seed);

    let mut bit_pos_sig = 32 * 8;
    for zi in &z {
        for &c_val in zi.coeffs.iter() {
            let z_val = crate::field::csubq(crate::field::caddq(c_val));
            let centered_z = z_val.wrapping_sub(Q & ((Q / 2).wrapping_sub(z_val) >> 31));
            let val =
                (centered_z.wrapping_add(ctx.gamma1 - 1) as u64) & ((1u64 << gamma1_bits) - 1);
            let bits = gamma1_bits;
            let byte_idx = bit_pos_sig / 8;
            let bit_off = bit_pos_sig % 8;
            sig[byte_idx] |= ((val & 0xFF) as u8) << bit_off;
            if bit_off + bits > 8 {
                sig[byte_idx + 1] |= ((val >> (8 - bit_off)) & 0xFF) as u8;
            }
            if bit_off + bits > 16 {
                sig[byte_idx + 2] |= ((val >> (16 - bit_off)) & 0xFF) as u8;
            }
            bit_pos_sig += bits;
        }
    }

    let h_enc = encode_hint::<P>(&h);
    let h_start = 32 + z_bytes;
    sig[h_start..h_start + h_bytes].copy_from_slice(&h_enc[..h_bytes]);

    (sig, valid)
}

/// Decode the public key vector t₁ from the serialized public key.
fn decode_t1_from_pk<P: Params>(pk: &[u8]) -> Vec<Poly> {
    let pk_enc_bits = 10usize;
    let mut t1 = vec![Poly::new(); P::K];
    let mut bit_pos = 32 * 8;
    for poly in &mut t1 {
        bit_pos = unpack_bits(pk, &mut *poly.coeffs, pk_enc_bits, bit_pos);
    }
    t1
}

/// Compute μ = CRH(tr || msg) for verification, deriving tr = H(pk) first.
fn compute_mu_for_verification(pk: &[u8], prefix: &[u8], msg: &[u8]) -> [u8; 64] {
    let mu: [u8; 64] = {
        let mut shake = Shake256::default();
        shake.update(&pk[..32]); // rho
        shake.update(&pk[32..]); // t1_enc
        let mut tr = [0u8; 64];
        let mut reader = shake.finalize_xof();
        reader.read(&mut tr);
        hash_tr_msg_with_prefix(&tr, prefix, msg)
    };
    mu
}

/// Decode z from the signature and check ‖z‖∞ < γ₁ - β.
///
/// Returns the decoded z vector on success or `None` if the norm check fails.
fn decode_z_check_norm<P: Params>(
    sig: &[u8],
    gamma1_bits: usize,
    gamma1: i32,
    beta: i32,
) -> Option<Vec<Poly>> {
    let mut z = vec![Poly::new(); P::L];
    let mut bit_pos_z = 32 * 8;
    for zi in z.iter_mut() {
        bit_pos_z = unpack_bits(sig, &mut *zi.coeffs, gamma1_bits, bit_pos_z);
        for coeff in zi.coeffs.iter_mut() {
            *coeff -= gamma1 - 1;
        }
    }

    let z_max = z.iter().map(|zi| zi.infinity_norm()).max().unwrap_or(0);
    if z_max >= gamma1 - beta {
        return None;
    }
    Some(z)
}

/// Compute w₁ = A·z − c·(2^D · t₁) in the NTT domain, then reduce and inverse NTT.
fn compute_w1_ntt_domain<P: Params>(
    a: &[Vec<Poly>],
    z_ntt: &[Poly],
    c_ntt: &Poly,
    t1: &mut [Poly],
) -> Vec<Poly> {
    // w1 = A*z (NTT domain)
    let mut w1 = matrix_multiply::<P>(a, z_ntt);

    // t1 = c · NTT(2^D * t1)  (NTT domain, matches C ref)
    let d = i32::try_from(P::D).expect("P::D fits in i32");
    for i in 0..P::K {
        for coeff in t1[i].coeffs.iter_mut() {
            *coeff = coeff.wrapping_shl(u32::from_ne_bytes(d.to_ne_bytes()));
        }
        ntt(&mut t1[i]);
        let mut tmp = Poly::new();
        ntt_mul(c_ntt, &t1[i], &mut tmp);
        t1[i] = tmp;
    }

    // w1 = w1 - t1  (NTT domain raw subtraction, matches C ref)
    for i in 0..P::K {
        for j in 0..256 {
            w1[i].coeffs[j] = w1[i].coeffs[j].wrapping_sub(t1[i].coeffs[j]);
        }
    }

    // reduce + invntt (matches C ref)
    for w1i in w1.iter_mut() {
        for coeff in w1i.coeffs.iter_mut() {
            *coeff = crate::field::reduce32(*coeff);
        }
        inv_ntt(w1i);
    }

    // caddq (matches C ref)
    for w1i in w1.iter_mut() {
        for coeff in w1i.coeffs.iter_mut() {
            *coeff = crate::field::caddq(*coeff);
        }
    }

    w1
}

/// Decode the hint from the signature, apply it to w₁, and verify the challenge.
///
/// Returns `true` if the reconstructed c̃ matches c̃ from the signature.
fn decode_hint_and_verify_challenge<P: Params>(
    sig: &[u8],
    mu: &[u8; 64],
    w1: &mut [Poly],
    z_bytes: usize,
    gamma2: i32,
    c_tilde_seed: &[u8; 32],
) -> bool {
    // Decode hint from sig
    let h_bytes = P::OMEGA + P::K;
    let h_start = 32 + z_bytes;
    let h_enc = &sig[h_start..h_start + h_bytes];
    let mut h = vec![Poly::new(); P::K];
    let omega = P::OMEGA;
    let mut index = 0usize;
    for i in 0..P::K {
        let old_index = index;
        let boundary = h_enc[omega + i] as usize;
        if boundary < index || boundary > omega {
            return false;
        }
        while index < boundary {
            let pos = h_enc[index] as usize;
            if index > old_index && h_enc[index] <= h_enc[index - 1] {
                return false;
            }
            h[i].coeffs[pos] = 1;
            index += 1;
        }
    }

    if h_enc[index..omega].iter().any(|&b| b != 0) {
        return false;
    }

    // w1_corrected = use_hint(w1, h)
    // The reference first computes caddq, then decompose:
    for w1i in w1.iter_mut() {
        for coeff in w1i.coeffs.iter_mut() {
            *coeff = crate::field::caddq(*coeff);
        }
    }

    for i in 0..P::K {
        for j in 0..256 {
            w1[i].coeffs[j] = Poly::use_hint(w1[i].coeffs[j], h[i].coeffs[j], gamma2);
        }
    }

    // Encode w1_corrected
    let w1_prime_enc = encode_w1_high_bits::<P>(w1);

    // Compute c̃' = H(μ || w₁')
    let mut c_tilde_prime = [0u8; 64];
    {
        let mut shake = Shake256::default();
        shake.update(mu);
        shake.update(&w1_prime_enc);
        let mut reader = shake.finalize_xof();
        reader.read(&mut c_tilde_prime);
    }

    c_tilde_prime[..32] == c_tilde_seed[..]
}

pub(crate) fn sign<P: Params>(
    sk: &[u8],
    msg: &[u8],
    prefix: &[u8],
    rnd: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    if sk.len() != P::SECRET_KEY_BYTES {
        return Err(Error::InvalidSecretKeyLength);
    }

    if prefix.len() > 255 {
        return Err(Error::InvalidContextLength);
    }
    if msg.len() > (1 << 20) {
        return Err(Error::InvalidMessageLength);
    }

    let rho = &sk[..32];
    let k = &sk[32..64];
    let tr = &sk[64..128];

    let (s1, s2, t0) = decode_signing_key::<P>(sk);
    let (s1_ntt, s2_ntt, t0_ntt, a) = prepare_signing_matrices::<P>(&s1, &s2, &t0, rho);
    let (mu, rhoprime) = compute_message_expansion(k, tr, prefix, msg, rnd);

    let gamma1 = i32::try_from(P::GAMMA1).expect("P::GAMMA1 fits in i32");
    let gamma2 = i32::try_from(P::GAMMA2).expect("P::GAMMA2 fits in i32");
    let tau = P::TAU;
    let beta = i32::try_from(P::BETA).expect("P::BETA fits in i32");

    let mut y = vec![Poly::new(); P::L];
    let mut nonce: u16 = 0;

    // Pre-compute sig_len (parameter-dependent, not secret).
    let gamma1_bits = if gamma1 == (1 << 17) { 18 } else { 20 };
    let z_bytes = (P::L * 256 * gamma1_bits).div_ceil(8);
    let sig_len = 32 + z_bytes + P::OMEGA + P::K;
    let mut best_sig = vec![0u8; sig_len];
    let mut found = Choice::from(0u8);

    for _ in 0..MAX_ATTEMPTS {
        sample_mask_y(
            &mut y,
            &rhoprime,
            &mut nonce,
            usize::try_from(gamma1).expect("value fits in usize"),
        );

        let (_w, w1, w0) = compute_w_and_decompose::<P>(&a, &y, gamma2);
        let (c_tilde_seed, c) = compute_challenge::<P>(&mu, &w1, tau);
        let ctx = SignResponseCtx {
            c: &c,
            c_tilde_seed: &c_tilde_seed,
            s1_ntt: &s1_ntt,
            s2_ntt: &s2_ntt,
            t0_ntt: &t0_ntt,
            y: &y,
            w0: &w0,
            gamma1,
            gamma2,
            beta,
        };
        let (sig, valid) = try_sign_response_ct::<P>(&ctx);

        // CT mux: branching would leak iteration count.
        let store = !found & valid;
        for i in 0..sig_len {
            best_sig[i] = u8::conditional_select(&best_sig[i], &sig[i], store);
        }
        found |= store;
    }

    // Unavoidable branch: caller must know success/failure.
    if found.unwrap_u8() == 0 {
        return Err(Error::SigningFailed);
    }
    Ok(best_sig)
}

#[must_use]
pub(crate) fn verify<P: Params>(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    verify_with_prefix::<P>(pk, msg, &[0u8, 0u8], sig)
}

#[must_use]
pub(crate) fn verify_with_prefix<P: Params>(
    pk: &[u8],
    msg: &[u8],
    prefix: &[u8],
    sig: &[u8],
) -> bool {
    let gamma1 = i32::try_from(P::GAMMA1).expect("P::GAMMA1 fits in i32");
    let gamma2 = i32::try_from(P::GAMMA2).expect("P::GAMMA2 fits in i32");
    let beta = i32::try_from(P::BETA).expect("P::BETA fits in i32");
    let gamma1_bits = if gamma1 == (1 << 17) { 18 } else { 20 };
    let z_bytes = (P::L * 256 * gamma1_bits).div_ceil(8);
    let h_bytes = P::OMEGA + P::K;
    let expected_sig_len = 32 + z_bytes + h_bytes;

    if pk.len() != P::PUBLIC_KEY_BYTES || sig.len() != expected_sig_len {
        return false;
    }

    if prefix.len() > 255 {
        return false;
    }
    if msg.len() > (1 << 20) {
        return false;
    }

    let rho = &pk[..32];

    let mut t1 = decode_t1_from_pk::<P>(pk);

    let mut a = vec![vec![Poly::new(); P::L]; P::K];
    expand_matrix::<P>(&mut a, rho);
    for row in a.iter_mut() {
        for val in row.iter_mut() {
            ntt(val);
        }
    }

    let mu = compute_mu_for_verification(pk, prefix, msg);

    let mut c_tilde_seed = [0u8; 32];
    c_tilde_seed.copy_from_slice(&sig[..32]);
    let c = sample_in_ball(&c_tilde_seed, P::TAU);
    let mut c_ntt = c.clone();
    ntt(&mut c_ntt);

    let z = match decode_z_check_norm::<P>(sig, gamma1_bits, gamma1, beta) {
        Some(z) => z,
        None => {
            return false;
        }
    };

    let mut z_ntt = z.clone();
    for zi in z_ntt.iter_mut() {
        for coeff in zi.coeffs.iter_mut() {
            *coeff = crate::field::reduce32(*coeff);
        }
        ntt(zi);
    }

    let mut w1 = compute_w1_ntt_domain::<P>(&a, &z_ntt, &c_ntt, &mut t1);

    decode_hint_and_verify_challenge::<P>(sig, &mu, &mut w1, z_bytes, gamma2, &c_tilde_seed)
}
