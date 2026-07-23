use crate::params::*;
use backbone_pqcrypto_internals::secret::SecretVec;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Sample polynomial from a centered binomial distribution using SHAKE256.
///
/// η=3 needs 384 bytes, η=2 needs 256 bytes of randomness.
pub(crate) fn sample_cbd(seed_32: &[u8; 32], eta: usize, nonce: u8) -> [i16; 256] {
    let buflen = 4 * eta * N / 8;
    let mut buf = SecretVec::<u8>::new(buflen);

    let mut input = [0u8; 33];
    input[..32].copy_from_slice(seed_32);
    input[32] = nonce;

    let mut hasher = Shake256::default();
    hasher.update(&input);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut buf);

    let mut coeffs = [0i16; N];
    for i in 0..N {
        let mut a = 0u32;
        let mut b = 0u32;
        for j in 0..eta {
            let byte_idx_a = (eta * (2 * i) + j) / 8;
            let bit_idx_a = (eta * (2 * i) + j) % 8;
            let byte_idx_b = (eta * (2 * i + 1) + j) / 8;
            let bit_idx_b = (eta * (2 * i + 1) + j) % 8;
            if byte_idx_a < buflen {
                a += u32::from((buf[byte_idx_a] >> bit_idx_a) & 1);
            }
            if byte_idx_b < buflen {
                b += u32::from((buf[byte_idx_b] >> bit_idx_b) & 1);
            }
        }
        let a_i16 = i16::try_from(a).expect("a (max eta=3) fits in i16");
        let b_i16 = i16::try_from(b).expect("b (max eta=3) fits in i16");
        let diff = a_i16.wrapping_sub(b_i16);
        coeffs[i] = diff;
    }
    coeffs
}

/// Deterministically sample a k×k matrix A in NTT domain from seed ρ (32 bytes).
/// Uses SHAKE-128 with rejection sampling matching the C reference:
/// extracts two 12-bit values from every 3 bytes.
pub(crate) fn sample_ntt<const K: usize>(rho: &[u8; 32]) -> [[[i16; N]; K]; K] {
    let mut a = [[[0i16; N]; K]; K];
    let mut buf = [0u8; 672];

    for i in 0..K {
        for j in 0..K {
            let mut input = [0u8; 34];
            input[..32].copy_from_slice(rho);
            input[32] = u8::try_from(j).expect("j < 256");
            input[33] = u8::try_from(i).expect("i < 256");

            let mut hasher = sha3::Shake128::default();
            hasher.update(&input);
            let mut reader = hasher.finalize_xof();
            reader.read(&mut buf);
            let mut coeff_idx = 0usize;
            let mut buf_idx = 0usize;
            while coeff_idx < 256 {
                if buf_idx + 3 > 672 {
                    buf_idx = 0;
                    reader.read(&mut buf);
                }
                let val0 = (u16::from(buf[buf_idx]) | (u16::from(buf[buf_idx + 1]) << 8)) & 0xFFF;
                let val1 = (u16::from(buf[buf_idx + 1]) >> 4) | (u16::from(buf[buf_idx + 2]) << 4);
                buf_idx += 3;
                if val0 < u16::try_from(Q).expect("Q fits in u16") {
                    let v0 = i16::try_from(val0).expect("val0 < Q fits in i16");
                    a[i][j][coeff_idx] = v0;
                    coeff_idx += 1;
                }
                if coeff_idx < 256 && val1 < u16::try_from(Q).expect("Q fits in u16") {
                    let v1 = i16::try_from(val1).expect("val1 < Q fits in i16");
                    a[i][j][coeff_idx] = v1;
                    coeff_idx += 1;
                }
            }
        }
    }
    a
}
