//! NTT operations using backend dispatch.
//! Re-exports from the selected backend (soft or avx2).

#[cfg(test)]
use crate::params::N;

/// Zeta constants for the NTT (ML-KEM / FIPS 203).
pub(crate) const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

pub(crate) use crate::backends::{invntt, ntt, poly_basemul};

/// Direct O(N²) NTT — evaluates even and odd parts of f at N/2 = 128 points.
#[cfg(test)]
pub(crate) fn ntt_direct(a: &[i16; N]) -> [i16; N] {
    let mut out = [0i16; N];
    for i in 0..128 {
        let zeta_k = pow_zeta((2 * bit_rev7(i) + 1) as u32);
        let mut sum_even = 0i32;
        let mut sum_odd = 0i32;
        let mut pow = 1i32;
        for j in 0..128 {
            sum_even = (sum_even + i32::from(a[2 * j]) * pow) % 3329;
            sum_odd = (sum_odd + i32::from(a[2 * j + 1]) * pow) % 3329;
            pow = (pow * zeta_k) % 3329;
        }
        if sum_even > 3329 / 2 {
            sum_even -= 3329;
        }
        if sum_odd > 3329 / 2 {
            sum_odd -= 3329;
        }
        out[2 * i] = sum_even as i16;
        out[2 * i + 1] = sum_odd as i16;
    }
    out
}

#[cfg(test)]
fn bit_rev7(x: usize) -> usize {
    let mut r = 0usize;
    for i in 0..7 {
        r = (r << 1) | ((x >> i) & 1);
    }
    r
}

#[cfg(test)]
fn pow_zeta(exp: u32) -> i32 {
    let exp = exp % 512;
    let mut r = 1i32;
    for _ in 0..exp {
        r = (r * 17) % 3329;
    }
    r
}

#[cfg(test)]
fn invntt_direct(a: &[i16; N]) -> [i16; N] {
    let n_inv = mod_inv(128);
    let mut out = [0i16; N];
    for j in 0..128 {
        let mut sum_even = 0i32;
        let mut sum_odd = 0i32;
        for i in 0..128 {
            let zeta_k = pow_zeta((2 * bit_rev7(i) + 1) as u32);
            let zeta_k_neg_j = pow_inv(zeta_k, j as u32);
            sum_even = (sum_even + i32::from(a[2 * i]) * zeta_k_neg_j) % 3329;
            sum_odd = (sum_odd + i32::from(a[2 * i + 1]) * zeta_k_neg_j) % 3329;
        }
        sum_even = (sum_even * n_inv) % 3329;
        sum_odd = (sum_odd * n_inv) % 3329;
        if sum_even > 3329 / 2 {
            sum_even -= 3329;
        }
        if sum_odd > 3329 / 2 {
            sum_odd -= 3329;
        }
        out[2 * j] = sum_even as i16;
        out[2 * j + 1] = sum_odd as i16;
    }
    out
}

#[cfg(test)]
fn pow_inv(base: i32, exp: u32) -> i32 {
    let exp_mod = 3329 - 1 - exp;
    let mut r = 1i32;
    let mut b = base;
    let mut e = exp_mod;
    while e > 0 {
        if e & 1 == 1 {
            r = (r * b) % 3329;
        }
        b = (b * b) % 3329;
        e >>= 1;
    }
    r
}

#[cfg(test)]
fn mod_inv(x: i32) -> i32 {
    let mut t = 0i32;
    let mut newt = 1i32;
    let mut r = 3329;
    let mut newr = x;
    while newr != 0 {
        let q = r / newr;
        (t, newt) = (newt, t - q * newt);
        (r, newr) = (newr, r - q * newr);
    }
    t.rem_euclid(3329)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_invntt_direct_roundtrip() {
        let mut a = [0i16; N];
        for i in 0..N {
            a[i] = (i % 3329) as i16;
        }
        let original = a;
        let ntt_out = ntt_direct(&a);
        let recovered = invntt_direct(&ntt_out);
        for i in 0..N {
            let r = i32::from(recovered[i]).rem_euclid(3329);
            let o = i32::from(original[i]).rem_euclid(3329);
            assert_eq!(r, o, "Direct roundtrip mismatch at {i}");
        }
    }

    #[test]
    fn test_ntt_invntt_roundtrip() {
        let mut a = [0i16; N];
        for i in 0..N {
            a[i] = (i % 3329) as i16;
        }
        let original = a;
        ntt(&mut a);
        invntt(&mut a);
        for i in 0..N {
            let got = i32::from(a[i]).rem_euclid(3329);
            let expected = (i32::from(original[i]) * 2285).rem_euclid(3329);
            assert_eq!(got, expected, "NTT + invNTT at {i}");
        }
    }

    #[test]
    fn test_ntt_based_multiply() {
        let mut a = [0i16; N];
        let mut b = [0i16; N];
        a[0] = 1;
        a[1] = 2;
        b[0] = 3;
        b[1] = 4;
        let mut c_ref = [0i16; N];
        for i in 0..N {
            if a[i] == 0 {
                continue;
            }
            for j in 0..N {
                if b[j] == 0 {
                    continue;
                }
                let idx = if i + j < N { i + j } else { i + j - N };
                let sign: i32 = if i + j < N { 1 } else { -1 };
                let val = i32::from(c_ref[idx]) + sign * i32::from(a[i]) * i32::from(b[j]);
                c_ref[idx] = (val.rem_euclid(3329)) as i16;
            }
        }
        let mut a_ntt = a;
        let mut b_ntt = b;
        ntt(&mut a_ntt);
        ntt(&mut b_ntt);
        let mut c = [0i16; N];
        poly_basemul(&mut c, &a_ntt, &b_ntt);
        invntt(&mut c);
        for i in 0..8 {
            let c_i_norm = (i32::from(c[i]).rem_euclid(3329)) as i16;
            if c_i_norm != c_ref[i] {
                panic!(
                    "NTT multiply mismatch at {i}: got {} expected {}",
                    c_i_norm, c_ref[i]
                );
            }
        }
    }

    #[test]
    fn test_ntt_soft_vs_active() {
        let mut a = [0i16; N];
        for i in 0..N {
            a[i] = (i % 3329) as i16;
        }
        let mut a_soft = a;
        let mut a_active = a;
        crate::backends::soft::ntt(&mut a_soft);
        ntt(&mut a_active);
        for i in 0..N {
            let soft = i32::from(a_soft[i]).rem_euclid(3329);
            let active = i32::from(a_active[i]).rem_euclid(3329);
            assert_eq!(
                soft, active,
                "NTT mismatch at {i}: soft={} active={}",
                a_soft[i], a_active[i]
            );
        }
    }

    #[test]
    fn test_invntt_soft_vs_active() {
        let mut a = [0i16; N];
        for i in 0..N {
            a[i] = (i % 3329) as i16;
        }
        ntt(&mut a);
        let mut a_soft = a;
        let mut a_active = a;
        crate::backends::soft::invntt(&mut a_soft);
        invntt(&mut a_active);
        for i in 0..N {
            let soft = i32::from(a_soft[i]).rem_euclid(3329);
            let active = i32::from(a_active[i]).rem_euclid(3329);
            assert_eq!(
                soft, active,
                "invNTT mismatch at {i}: soft={} active={}",
                a_soft[i], a_active[i]
            );
        }
    }
}
