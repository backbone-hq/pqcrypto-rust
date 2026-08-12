//! ML-KEM core KEM operations: key generation, encapsulation, decapsulation.

use crate::error::Error;
use crate::field::{barrett_reduce, montgomery_reduce};
use crate::ntt;
use crate::params::*;
use crate::poly::{Poly, PolyVec};
use crate::sampling;
use alloc::vec::Vec;
use backbone_pqcrypto_internals::secret::{SecretArray, SecretVec};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Sha3_512, Shake256,
};
use subtle::{ConditionallySelectable, ConstantTimeEq};

fn g_hash(input: &[u8]) -> SecretArray<u8, 64> {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, input);
    let result = hasher.finalize();
    let mut out = SecretArray::<u8, 64>::new();
    out.copy_from_slice(&result);
    out
}

fn h_hash(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, input);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn j_hash(input: &[u8]) -> SecretArray<u8, 32> {
    let mut shake = Shake256::default();
    Update::update(&mut shake, input);
    let mut reader = shake.finalize_xof();
    let mut out = SecretArray::<u8, 32>::new();
    reader.read(out.as_mut());
    out
}

#[must_use]
/** Validate the structural integrity of an encapsulation key (ek). */
pub(crate) fn check_public_key<const K: usize>(ek: &[u8]) -> bool {
    if ek.len() != K * POLY_BYTES + 32 {
        return false;
    }

    let t_vec = PolyVec::<K>::decode_12(&ek[..K * POLY_BYTES]);
    let q = i16::try_from(Q).expect("Q fits in i16");
    let mut invalid = 0u16;
    for i in 0..K {
        for j in 0..N {
            invalid |= if t_vec.vec[i].coeffs[j] >= q { 1 } else { 0 };
        }
    }
    invalid == 0
}

#[must_use]
/** Validate the structural integrity of a decapsulation key (dk) by checking the embedded H(ek). */
pub(crate) fn check_secret_key<const K: usize>(dk: &[u8], pk_size: usize) -> bool {
    let s_enc_size = K * POLY_BYTES;
    if dk.len() != s_enc_size + pk_size + 64 {
        return false;
    }

    let dk_ek = &dk[s_enc_size..s_enc_size + pk_size];
    let dk_h = &dk[s_enc_size + pk_size..s_enc_size + pk_size + 32];
    let expected_h = h_hash(dk_ek);
    dk_h.ct_eq(&expected_h).unwrap_u8() == 1
}

/// ML-KEM.KeyGen_internal (FIPS 203 Section 6.1)
#[must_use]
pub(crate) fn keygen_internal<const K: usize>(
    eta1: usize,
    _eta2: usize,
    d: &[u8; 32],
    z: &[u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    let mut g_input = SecretArray::<u8, 33>::new();
    g_input[..32].copy_from_slice(d);
    g_input[32] = u8::try_from(K).expect("K fits in u8");
    let g_out = g_hash(g_input.as_ref());
    let mut rho = [0u8; 32];
    let mut sigma = SecretArray::<u8, 32>::new();
    rho.copy_from_slice(&g_out[..32]);
    sigma.copy_from_slice(&g_out[32..64]);

    let a = sampling::sample_ntt::<K>(&rho);

    let mut s = PolyVec::<K>::new();
    let mut e = PolyVec::<K>::new();
    for i in 0..K {
        s.vec[i].coeffs = SecretArray::from_array(sampling::sample_cbd(
            &sigma,
            eta1,
            u8::try_from(i).expect("i < 256"),
        ));
        e.vec[i].coeffs = SecretArray::from_array(sampling::sample_cbd(
            &sigma,
            eta1,
            u8::try_from(K + i).expect("K+i < 256"),
        ));
    }

    for i in 0..K {
        ntt::ntt(&mut s.vec[i].coeffs);
        ntt::ntt(&mut e.vec[i].coeffs);
    }

    let mut t_hat = [[0i16; N]; K];
    for i in 0..K {
        let mut sum = SecretArray::<i16, N>::new();
        for j in 0..K {
            let mut prod = SecretArray::<i16, N>::new();
            ntt::poly_basemul(&mut prod, &a[i][j], &s.vec[j].coeffs);
            for k in 0..N {
                sum[k] = barrett_reduce({
                    i16::try_from(i32::from(sum[k]) + i32::from(prod[k]))
                        .expect("sum of i16 values fits in i16")
                });
            }
        }
        for k in 0..N {
            sum[k] = montgomery_reduce(i32::from(sum[k]) * 1353);
        }
        for k in 0..N {
            sum[k] = barrett_reduce({
                i16::try_from(i32::from(sum[k]) + i32::from(e.vec[i].coeffs[k]))
                    .expect("sum of i16 values fits in i16")
            });
        }
        t_hat[i] = sum.into_inner();
    }

    let t_polyvec = PolyVec::<K>::from_arrays(&t_hat);
    let t_enc = t_polyvec.encode_12();

    let mut ek = Vec::with_capacity(K * POLY_BYTES + 32);
    ek.extend_from_slice(&t_enc);
    ek.extend_from_slice(&rho);

    let s_enc = s.encode_12();

    let h_ek = h_hash(&ek);
    let mut dk = Vec::with_capacity(s_enc.len() + ek.len() + 32 + 32);
    dk.extend_from_slice(&s_enc);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h_ek);
    dk.extend_from_slice(z);

    (ek, dk)
}

/// K-PKE.Encrypt (FIPS 203 Section 6.2)
pub(crate) fn pke_encrypt<const K: usize>(
    ek: &[u8],
    m: &[u8; 32],
    r: &[u8; 32],
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
) -> Result<Vec<u8>, Error> {
    if ek.len() < K * POLY_BYTES + 32 {
        return Err(Error::InvalidKeyLength);
    }
    let t_enc = &ek[..K * POLY_BYTES];
    let mut rho_arr = [0u8; 32];
    rho_arr.copy_from_slice(&ek[K * POLY_BYTES..]);

    let a = sampling::sample_ntt::<K>(&rho_arr);

    let mut y_coeffs = [(); K].map(|_| SecretArray::<i16, N>::new());
    for i in 0..K {
        y_coeffs[i] = SecretArray::from_array(sampling::sample_cbd(
            r,
            eta1,
            u8::try_from(i).expect("i < 256"),
        ));
    }
    let mut e1_coeffs = [(); K].map(|_| SecretArray::<i16, N>::new());
    for i in 0..K {
        e1_coeffs[i] = SecretArray::from_array(sampling::sample_cbd(
            r,
            eta2,
            u8::try_from(K + i).expect("K+i < 256"),
        ));
    }
    let e2_coeffs = SecretArray::from_array(sampling::sample_cbd(
        r,
        eta2,
        u8::try_from(2 * K).expect("2*K < 256"),
    ));

    let mut y_hat = y_coeffs;
    for i in 0..K {
        ntt::ntt(&mut y_hat[i]);
    }

    let mut u_hat = [[0i16; N]; K];
    for i in 0..K {
        let mut sum = SecretArray::<i16, N>::new();
        for j in 0..K {
            let mut prod = SecretArray::<i16, N>::new();
            ntt::poly_basemul(&mut prod, &a[j][i], &y_hat[j]);
            for k in 0..N {
                sum[k] = barrett_reduce({
                    i16::try_from(i32::from(sum[k]) + i32::from(prod[k]))
                        .expect("sum of i16 values fits in i16")
                });
            }
        }
        ntt::invntt(&mut sum);
        for k in 0..N {
            u_hat[i][k] = barrett_reduce({
                i16::try_from(i32::from(sum[k]) + i32::from(e1_coeffs[i][k]))
                    .expect("sum of i16 values fits in i16")
            });
        }
    }

    let t_vec = PolyVec::<K>::decode_12(t_enc);

    let mut v_ntt = [0i16; N];
    for i in 0..K {
        let mut prod = SecretArray::<i16, N>::new();
        ntt::poly_basemul(&mut prod, &t_vec.vec[i].coeffs, &y_hat[i]);
        for k in 0..N {
            v_ntt[k] = barrett_reduce({
                i16::try_from(i32::from(v_ntt[k]) + i32::from(prod[k]))
                    .expect("sum of i16 values fits in i16")
            });
        }
    }
    ntt::invntt(&mut v_ntt);
    for k in 0..N {
        v_ntt[k] = barrett_reduce({
            i16::try_from(i32::from(v_ntt[k]) + i32::from(e2_coeffs[k]))
                .expect("sum of i16 values fits in i16")
        });
    }

    let msg_poly = Poly::from_msg(m);
    for k in 0..N {
        v_ntt[k] = barrett_reduce({
            i16::try_from(i32::from(v_ntt[k]) + i32::from(msg_poly.coeffs[k]))
                .expect("sum of i16 values fits in i16")
        });
    }

    let u_polyvec = PolyVec::<K>::from_arrays(&u_hat);
    let c1 = u_polyvec.compress(du).byte_encode(du);
    let v_poly = Poly::from_coeffs(v_ntt);
    let c2 = v_poly.compress(dv).byte_encode(dv);

    let mut ct = Vec::with_capacity(c1.len() + c2.len());
    ct.extend_from_slice(&c1);
    ct.extend_from_slice(&c2);
    Ok(ct)
}

/// K-PKE.Decrypt (FIPS 203 Section 6.3)
pub(crate) fn pke_decrypt<const K: usize>(
    s_enc: &[u8],
    ct: &[u8],
    du: usize,
    dv: usize,
) -> Result<SecretArray<u8, 32>, Error> {
    let s_poly_vec = PolyVec::<K>::decode_12(s_enc);

    let c1_size = (du * K * N).div_ceil(8);
    let c2_size = (dv * N).div_ceil(8);

    if ct.len() < c1_size + c2_size {
        return Err(Error::InvalidCiphertextLength);
    }
    if s_enc.len() < K * POLY_BYTES {
        return Err(Error::InvalidSecretKeyLength);
    }

    let u_vec = PolyVec::<K>::byte_decode(&ct[..c1_size], du);
    let u_decompressed = u_vec.decompress(du);

    let v_poly = Poly::byte_decode(&ct[c1_size..c1_size + c2_size], dv);
    let v_decompressed = v_poly.decompress(dv);

    let mut u_ntt = [[0i16; N]; K];
    for i in 0..K {
        for j in 0..N {
            u_ntt[i][j] = u_decompressed.vec[i].coeffs[j];
        }
        ntt::ntt(&mut u_ntt[i]);
    }
    let mut w_hat = SecretArray::<i16, N>::new();
    for i in 0..K {
        let mut prod = SecretArray::<i16, N>::new();
        ntt::poly_basemul(&mut prod, &s_poly_vec.vec[i].coeffs, &u_ntt[i]);
        for k in 0..N {
            w_hat[k] = barrett_reduce({
                i16::try_from(i32::from(w_hat[k]) + i32::from(prod[k]))
                    .expect("sum of i16 values fits in i16")
            });
        }
    }
    ntt::invntt(&mut w_hat);
    let mut w = SecretArray::<u16, N>::new();
    for k in 0..N {
        w[k] = u16::try_from(
            (i32::from(v_decompressed.coeffs[k]) - i32::from(w_hat[k])).rem_euclid(Q),
        )
        .expect("rem_euclid(Q) yields u16-safe value");
    }

    let mut msg = SecretArray::<u8, 32>::new();
    for i in 0..32 {
        msg[i] = 0;
        for j in 0..8 {
            let coeff = i32::from(w[8 * i + j]);
            let t = ((coeff * 2 + (Q / 2)) / Q) & 1;
            let bit = u8::try_from(t).expect("t is 0 or 1, fits in u8");
            msg[i] |= bit << j;
        }
    }
    Ok(msg)
}

/// Result of a successful encapsulation.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Encapsulation {
    pub shared_secret: [u8; 32],
    pub ciphertext: Vec<u8>,
}

// Redacting Debug: never print the shared secret.
impl core::fmt::Debug for Encapsulation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Encapsulation")
            .field("ciphertext", &self.ciphertext)
            .field("shared_secret", &"[REDACTED]")
            .finish()
    }
}

/// ML-KEM.Encaps_internal (FIPS 203 Section 6.2)
pub(crate) fn encaps_internal<const K: usize>(
    ek: &[u8],
    m: &[u8; 32],
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
) -> Result<Encapsulation, Error> {
    let h_ek = h_hash(ek);
    let mut g_input = SecretArray::<u8, 64>::new();
    g_input[..32].copy_from_slice(m);
    g_input[32..64].copy_from_slice(&h_ek);
    let g_out = g_hash(g_input.as_ref());
    let mut k_inner = SecretArray::<u8, 32>::new();
    let mut r = SecretArray::<u8, 32>::new();
    k_inner.copy_from_slice(&g_out[..32]);
    r.copy_from_slice(&g_out[32..64]);
    let ct = pke_encrypt::<K>(ek, m, &r, eta1, eta2, du, dv)?;

    Ok(Encapsulation {
        shared_secret: k_inner.into_inner(), // FIPS 203 Algorithm 14: return K = G(m‖H(ek))[0..32]
        ciphertext: ct,
    })
}

/// ML-KEM.Decaps_internal (FIPS 203 Section 6.3)
pub(crate) fn decaps_internal<const K: usize>(
    dk: &[u8],
    ct: &[u8],
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
    pk_size: usize,
) -> Result<[u8; 32], Error> {
    let s_enc_size = K * POLY_BYTES;

    if dk.len() != s_enc_size + pk_size + 64 {
        return Err(Error::InvalidSecretKeyLength);
    }
    if !check_secret_key::<K>(dk, pk_size) {
        return Err(Error::InvalidSecretKey);
    }

    let dk_s = &dk[..s_enc_size];
    let dk_ek = &dk[s_enc_size..s_enc_size + pk_size];
    let dk_h = &dk[s_enc_size + pk_size..s_enc_size + pk_size + 32];
    let dk_z = &dk[s_enc_size + pk_size + 32..s_enc_size + pk_size + 64];

    let m_prime = pke_decrypt::<K>(dk_s, ct, du, dv)?;

    let mut g_input = SecretArray::<u8, 64>::new();
    g_input[..32].copy_from_slice(&*m_prime);
    g_input[32..64].copy_from_slice(dk_h);
    let g_out = g_hash(g_input.as_ref());
    let mut k_prime = SecretArray::<u8, 32>::new();
    let mut r_prime = SecretArray::<u8, 32>::new();
    k_prime.copy_from_slice(&g_out[..32]);
    r_prime.copy_from_slice(&g_out[32..64]);

    let ct_prime = pke_encrypt::<K>(dk_ek, &m_prime, &r_prime, eta1, eta2, du, dv)?;

    let fail = ct.ct_ne(&ct_prime);
    let mut rejection_input = SecretVec::<u8>::new(32 + ct.len());
    rejection_input[..32].copy_from_slice(dk_z);
    rejection_input[32..].copy_from_slice(ct);
    let rejection_key = j_hash(&rejection_input);

    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::conditional_select(&k_prime[i], &rejection_key[i], fail); // FIPS 203 §6.3: valid → K′, invalid → J(z‖c)
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss
    )]
    use super::*;

    #[test]
    fn test_pke_encrypt_decrypt_roundtrip() {
        const K: usize = 2;
        let d = [0u8; 32];
        let z = [0u8; 32];
        let (ek, dk) = keygen_internal::<K>(3, 2, &d, &z);
        let s_enc = &dk[..K * 384];

        let msg = [0u8; 32];
        let r = [0xCDu8; 32];
        let ct = pke_encrypt::<K>(&ek, &msg, &r, 3, 2, 10, 4).expect("pke_encrypt should succeed");
        let dec = pke_decrypt::<K>(s_enc, &ct, 10, 4).expect("pke_decrypt should succeed");
        assert_eq!(msg, *dec, "PKE with msg=0 should recover 0");

        let r2 = [0u8; 32];
        let ct2 =
            pke_encrypt::<K>(&ek, &msg, &r2, 3, 2, 10, 4).expect("pke_encrypt should succeed");
        let dec2 = pke_decrypt::<K>(s_enc, &ct2, 10, 4).expect("pke_decrypt should succeed");
        assert_eq!(msg, *dec2, "PKE with msg=0, r=[0;32] should recover 0");

        for trial in 0..256 {
            let mut test_msg = [0u8; 32];
            for i in 0..32 {
                test_msg[i] = ((trial * 7 + i * 13) % 256) as u8;
            }
            let test_r = [trial as u8; 32];
            let ct_t = pke_encrypt::<K>(&ek, &test_msg, &test_r, 3, 2, 10, 4)
                .expect("pke_encrypt should succeed");
            let dec_t = pke_decrypt::<K>(s_enc, &ct_t, 10, 4).expect("pke_decrypt should succeed");
            assert_eq!(
                test_msg, *dec_t,
                "PKE roundtrip failed at trial {} with r=[{};32]",
                trial, trial
            );
        }
    }
}
