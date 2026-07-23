//! ML-DSA (FIPS 204) Matrix Generation
//! Expansion of seed into matrix A using SHAKE128

use crate::params::Params;
use crate::poly::Poly;
use alloc::vec::Vec;
use sha3::{digest::ExtendableOutput, digest::Update, digest::XofReader, Shake128};

pub(crate) fn expand_matrix<P: Params>(a: &mut [Vec<Poly>], rho: &[u8]) {
    for (i, row) in a.iter_mut().enumerate().take(P::K) {
        for (j, poly) in row.iter_mut().enumerate().take(P::L) {
            let mut shake = Shake128::default();
            shake.update(rho);
            shake.update(&[
                u8::try_from(j).expect("j < 256"),
                u8::try_from(i).expect("i < 256"),
            ]);

            let mut reader = shake.finalize_xof();
            // FIPS 204 rejection sampling to fill a[i][j]
            let block = 168;
            let mut buf = [0u8; 168];
            let buf = &mut buf[..block];
            let mut buf_pos = block;
            let mut p = Poly::new();
            let mut coeff_idx = 0;
            while coeff_idx < 256 {
                if buf_pos + 3 > buf.len() {
                    reader.read(buf);
                    buf_pos = 0;
                }
                let val = i32::from(buf[buf_pos])
                    | (i32::from(buf[buf_pos + 1]) << 8)
                    | (i32::from(buf[buf_pos + 2]) << 16);
                buf_pos += 3;
                let val = val & 0x7FFFFF;
                if val < 8380417 {
                    p.coeffs[coeff_idx] = val;
                    coeff_idx += 1;
                }
            }
            *poly = p;
        }
    }
}
