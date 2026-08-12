use crate::gf;
use backbone_pqcrypto_internals::secret::SecretVec;

/// Evaluate polynomial `f` (degree `sys_t`, leading coeff `f[sys_t]`) at `a`.
fn eval_poly<const GFBITS: usize>(f: &[u16], a: u16, sys_t: usize) -> u16 {
    let mut r = f[sys_t];
    for i in (0..sys_t).rev() {
        r = gf::gf_mul::<GFBITS>(r, a);
        r = gf::gf_add(r, f[i]);
    }
    r
}

/// Syndrome computation.
///
/// Input:
///   `f`     – Goppa polynomial (`f[0..sys_t]`, `f[sys_t]` = 1)
///   roots     – support (roots[0..sys_n-1])
///   r     – received word (sys_n/8 bytes)
/// Output:
///   out   – syndrome (out.len() must be >= 2*sys_t)
pub(crate) fn synd<const GFBITS: usize>(
    out: &mut [u16],
    f: &[u16],
    roots: &[u16],
    r: &[u8],
    sys_n: usize,
    sys_t: usize,
) {
    for j in 0..2 * sys_t {
        out[j] = 0;
    }
    for i in 0..sys_n {
        let c_mask = 0u16.wrapping_sub(u16::from((r[i >> 3] >> (i & 7)) & 1));
        let e = eval_poly::<GFBITS>(f, roots[i], sys_t);
        let e_inv = gf::gf_inv::<GFBITS>(gf::gf_sq::<GFBITS>(e));
        let mut acc = e_inv;
        for j in 0..2 * sys_t {
            out[j] ^= acc & c_mask;
            acc = gf::gf_mul::<GFBITS>(acc, roots[i]);
        }
    }
}

/// Berlekamp-Massey algorithm.
///
/// Input:  s     – syndrome (s[0..2*sys_t-1])
/// Output: out   – error locator poly (out.len() must be >= sys_t+1)
pub(crate) fn bm<const GFBITS: usize>(out: &mut [u16], s: &[u16], sys_t: usize) {
    let mut c_poly = SecretVec::<u16>::new(sys_t + 1);
    let mut b_poly = SecretVec::<u16>::new(sys_t + 1);
    let mut tmp_poly = SecretVec::<u16>::new(sys_t + 1);

    b_poly[1] = 1;
    c_poly[0] = 1;

    let mut b: u16 = 1;
    let mut l_len: u16 = 0;

    for n_iter in 0..(2 * sys_t) {
        let mu = if n_iter <= sys_t { n_iter } else { sys_t };
        let mut d: u16 = 0;
        for i in 0..=mu {
            d ^= gf::gf_mul::<GFBITS>(c_poly[i], s[n_iter - i]);
        }

        let mut mne: u16 = d;
        mne = mne.wrapping_sub(1);
        mne >>= 15;
        mne = mne.wrapping_sub(1);

        let mut mle: u16 = u16::try_from(n_iter).expect("n_iter fits in u16");
        mle = mle.wrapping_sub(2 * l_len);
        mle >>= 15;
        mle = mle.wrapping_sub(1);
        mle &= mne;

        tmp_poly.copy_from_slice(&c_poly);

        let f = gf::gf_frac::<GFBITS>(b, d);

        for i in 0..=sys_t {
            c_poly[i] ^= gf::gf_mul::<GFBITS>(f, b_poly[i]) & mne;
        }

        l_len = (l_len & !mle)
            | (((u16::try_from(n_iter).expect("n_iter fits in u16")) + 1 - l_len) & mle);

        for i in 0..=sys_t {
            b_poly[i] = (b_poly[i] & !mle) | (tmp_poly[i] & mle);
        }

        b = (b & !mle) | (d & mle);

        for i in (1..=sys_t).rev() {
            b_poly[i] = b_poly[i - 1];
        }
        b_poly[0] = 0;
    }

    for i in 0..=sys_t {
        out[i] = c_poly[sys_t - i];
    }
}

/// Evaluate error locator polynomial at every support point.
///
/// Input:  locator[0..sys_t], roots[0..sys_n-1]
/// Output: `out[0..sys_n-1]` = locator(`roots[i]`)
pub(crate) fn root<const GFBITS: usize>(
    out: &mut [u16],
    locator: &[u16],
    roots: &[u16],
    sys_n: usize,
    sys_t: usize,
) {
    for i in 0..sys_n {
        out[i] = eval_poly::<GFBITS>(locator, roots[i], sys_t);
    }
}

///
/// Given Goppa polynomial `f`, support `roots`, and ciphertext `c`,
/// decode and verify the error vector.
///
/// Returns `(e, valid)` — error vector and success flag (1 = ok, 0 = fail).
/// `e` is a zeroizing buffer; the caller moves its bytes into the secret key
/// format without any bare copy surviving.
pub(crate) fn decrypt_with_support<const GFBITS: usize>(
    f: &[u16],
    roots: &[u16],
    c: &[u8],
    sys_n: usize,
    sys_t: usize,
) -> (SecretVec<u8>, u8) {
    let mut s = SecretVec::<u16>::new(2 * sys_t);
    let mut s_cmp = SecretVec::<u16>::new(2 * sys_t);
    let mut locator = SecretVec::<u16>::new(sys_t + 1);
    let mut images = SecretVec::<u16>::new(sys_n);

    let ct_bytes = c.len();
    let nbytes = sys_n / 8;
    let mut r = SecretVec::<u8>::new(nbytes);
    r[..ct_bytes.min(nbytes)].copy_from_slice(&c[..ct_bytes.min(nbytes)]);

    synd::<GFBITS>(s.as_mut(), f, roots, r.as_ref(), sys_n, sys_t);

    bm::<GFBITS>(locator.as_mut(), s.as_ref(), sys_t);

    root::<GFBITS>(images.as_mut(), locator.as_ref(), roots, sys_n, sys_t);

    let nbytes = sys_n / 8;
    let mut e = SecretVec::<u8>::new(nbytes);
    let mut w: u16 = 0;
    for i in 0..sys_n {
        let t = gf::gf_iszero(images[i]) & 1;
        e[i >> 3] |= (t as u8) << (i & 7);
        w = w.wrapping_add(t);
    }

    synd::<GFBITS>(s_cmp.as_mut(), f, roots, e.as_ref(), sys_n, sys_t);

    let mut check: u16 = w ^ u16::try_from(sys_t).expect("sys_t ≤ 65535");
    for j in 0..2 * sys_t {
        check |= s[j] ^ s_cmp[j];
    }
    let valid = (check.wrapping_sub(1) >> 15) as u8;

    (e, valid)
}
