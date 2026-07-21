//! HQC CPA-secure PKE: keygen, encrypt, decrypt.
use crate::codec;
use crate::gf2x;
use crate::kem;
use crate::params::Params;
use crate::parsing;
use crate::vector;
use alloc::vec;
use pqcrypto_utils::secret::SecretVec;
use sha3::{
    digest::{ExtendableOutput, Update},
    Shake256,
};

/// PKE key generation wrapped in the KEM secret-key format.
/// `seed_pke` expands with I into `seed_dk || seed_ek`.
pub(crate) fn keygen<P: Params>(
    pk: &mut [u8],
    sk: &mut [u8],
    seed_pke: &[u8],
    sigma: &[u8],
    seed_kem: &[u8],
) {
    let keypair_seed = kem::hash_i::<P>(seed_pke);
    let seed_dk = &keypair_seed[..P::SEED_BYTES];
    let seed_ek = &keypair_seed[P::SEED_BYTES..];

    let mut x = SecretVec::<u64>::new(P::VEC_N_SIZE_64);
    let mut y = SecretVec::<u64>::new(P::VEC_N_SIZE_64);
    let mut dk_xof = Shake256::default();
    dk_xof.update(seed_dk);
    dk_xof.update(&[kem::XOF_DOMAIN]);
    let mut dk_reader = dk_xof.finalize_xof();
    vector::vect_set_random_fixed_weight_keygen_from_xof::<P, _>(&mut dk_reader, &mut y);
    vector::vect_set_random_fixed_weight_keygen_from_xof::<P, _>(&mut dk_reader, &mut x);

    // Expand public key
    let mut rand_pk = vec![0u8; P::VEC_N_SIZE_BYTES];
    kem::xof_fill(seed_ek, &mut rand_pk);

    let mut h = vec![0u64; P::VEC_N_SIZE_64];
    vector::vect_set_random::<P>(&rand_pk, &mut h);

    // Compute s = x + y·h
    let mut s = vec![0u64; P::VEC_N_SIZE_64];
    gf2x::vect_mul::<P>(&mut s, &y, &h);
    for i in 0..P::VEC_N_SIZE_64 {
        s[i] ^= x[i];
    }

    parsing::hqc_public_key_to_string::<P>(pk, seed_ek, &s);
    parsing::hqc_secret_key_to_string::<P>(sk, pk, seed_dk, sigma, seed_kem);
}

/// CPA encryption.
/// Ciphertext: u = r1 + r2·h, v = m·G + r2·s + e
pub(crate) fn encrypt<P: Params>(u: &mut [u64], v: &mut [u64], m: &[u8], theta: &[u8], pk: &[u8]) {
    let mut rand = SecretVec::new(4 * (P::OMEGA_R * 2 + P::OMEGA_E));
    kem::xof_fill(theta, &mut rand);

    let mut h = vec![0u64; P::VEC_N_SIZE_64];
    let mut s = vec![0u64; P::VEC_N_SIZE_64];
    let mut pk_rand = vec![0u8; P::VEC_N_SIZE_BYTES];
    kem::xof_fill(&pk[..P::SEED_BYTES], &mut pk_rand);
    vector::vect_set_random::<P>(&pk_rand, &mut h);
    parsing::load8_arr(&mut s, &pk[P::SEED_BYTES..]);

    let mut r1 = SecretVec::<u64>::new(P::VEC_N_SIZE_64);
    let mut r2 = SecretVec::<u64>::new(P::VEC_N_SIZE_64);
    let mut e = SecretVec::<u64>::new(P::VEC_N_SIZE_64);
    vector::vect_set_random_fixed_weight::<P>(&rand[..4 * P::OMEGA_R], &mut r2, P::OMEGA_R);
    let e_start = 4 * P::OMEGA_R;
    let e_end = e_start + 4 * P::OMEGA_E;
    vector::vect_set_random_fixed_weight::<P>(&rand[e_start..e_end], &mut e, P::OMEGA_E);
    vector::vect_set_random_fixed_weight::<P>(&rand[e_end..], &mut r1, P::OMEGA_R);

    let mut tmp = SecretVec::<u64>::new(P::VEC_N_SIZE_64);
    gf2x::vect_mul::<P>(&mut tmp, &r2, &h);
    vector::vect_add(u, &r1, &tmp, P::VEC_N_SIZE_64);

    let mut em = SecretVec::<u64>::new(P::VEC_N1N2_SIZE_64);
    codec::encode::<P>(&mut em, m);

    let mut v_vec = SecretVec::<u64>::new(P::VEC_N_SIZE_64);
    gf2x::vect_mul::<P>(&mut v_vec, &r2, &s);
    for i in 0..P::VEC_N_SIZE_64 {
        v_vec[i] ^= e[i];
    }
    for i in 0..P::VEC_N1N2_SIZE_64 {
        v_vec[i] ^= em[i];
    }
    v.copy_from_slice(&v_vec[..P::VEC_N1N2_SIZE_64]);
}

/// CPA decryption.
/// m = decode(v - u·y)
pub(crate) fn decrypt<P: Params>(m: &mut [u8], u: &[u64], v: &[u64], sk: &[u8]) {
    let mut y = SecretVec::<u64>::new(P::VEC_N_SIZE_64);
    let seed_dk = &sk[P::PK_BYTES..P::PK_BYTES + P::SEED_BYTES];
    vector::vect_set_random_fixed_weight_keygen::<P>(seed_dk, &mut y);

    // v - u·y
    let mut tmp = vec![0u64; P::VEC_N_SIZE_64];
    gf2x::vect_mul::<P>(&mut tmp, &y, u);

    let mut v_full = vec![0u64; P::VEC_N_SIZE_64];
    v_full[..P::VEC_N1N2_SIZE_64].copy_from_slice(&v[..P::VEC_N1N2_SIZE_64]);
    for i in 0..P::VEC_N_SIZE_64 {
        v_full[i] ^= tmp[i];
    }

    codec::decode::<P>(m, &v_full);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{Hqc128, Params};

    #[test]
    fn test_hqc1_keygen_layout() {
        let seed_pke = [0xabu8; Hqc128::SEED_BYTES];
        let sigma = [0x42u8; Hqc128::VEC_K_SIZE_BYTES];
        let seed_kem = [0x11u8; Hqc128::SEED_BYTES];
        let mut pk = vec![0u8; Hqc128::PK_BYTES];
        let mut sk = vec![0u8; Hqc128::SK_BYTES];

        keygen::<Hqc128>(&mut pk, &mut sk, &seed_pke, &sigma, &seed_kem);

        assert_eq!(&sk[..Hqc128::PK_BYTES], pk.as_slice());
        assert_eq!(
            &sk[Hqc128::PK_BYTES + Hqc128::SEED_BYTES
                ..Hqc128::PK_BYTES + Hqc128::SEED_BYTES + Hqc128::VEC_K_SIZE_BYTES],
            sigma.as_slice()
        );
        assert_eq!(
            &sk[Hqc128::PK_BYTES + Hqc128::SEED_BYTES + Hqc128::VEC_K_SIZE_BYTES..],
            seed_kem.as_slice()
        );
    }
}
