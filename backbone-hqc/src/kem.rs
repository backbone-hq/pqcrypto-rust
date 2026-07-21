//! HQC KEM: keypair, encaps, decaps with FO transform (IND-CCA2).
//! Uses the Fujisaki-Okamoto transform for CCA security.

use crate::error::Error;
use crate::hqc;
use crate::params::Params;
use crate::parsing;
use alloc::vec;
use alloc::vec::Vec;
use backbone_pqcrypto_internals::secret::SecretVec;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Sha3_512, Shake256,
};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

/// Domain separation constant for PRNG.
pub(crate) const PRNG_DOMAIN: u8 = 0;
/// Domain separation constant for SHAKE-256 XOF expansion.
pub(crate) const XOF_DOMAIN: u8 = 1;
/// Domain separation constant for G function (FO transform).
pub(crate) const G_FCT_DOMAIN: u8 = 0;
/// Domain separation constant for H function.
pub(crate) const H_FCT_DOMAIN: u8 = 1;
/// Domain separation constant for I function.
pub(crate) const I_FCT_DOMAIN: u8 = 2;
/// Domain separation constant for J function.
pub(crate) const J_FCT_DOMAIN: u8 = 3;

/// Fill a buffer with SHAKE-256 XOF output seeded with `seed` + domain byte.
/// Uses PRNG_DOMAIN (0) matching the C reference's seedexpander.
pub(crate) fn prng_fill(seed: &[u8], out: &mut [u8]) {
    let mut hash = Shake256::default();
    hash.update(seed);
    hash.update(&[PRNG_DOMAIN]);
    let mut reader = hash.finalize_xof();
    reader.read(out);
}

/// Fill a buffer using the reference SHAKE-256 XOF expansion.
pub(crate) fn xof_fill(seed: &[u8], out: &mut [u8]) {
    let mut hash = Shake256::default();
    hash.update(seed);
    hash.update(&[XOF_DOMAIN]);
    let mut reader = hash.finalize_xof();
    reader.read(out);
}

pub(crate) fn hash_i<P: Params>(seed: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, &seed[..P::SEED_BYTES]);
    Digest::update(&mut hasher, [I_FCT_DOMAIN]);
    hasher.finalize().into()
}

fn hash_h<P: Params>(ek: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, &ek[..P::PK_BYTES]);
    Digest::update(&mut hasher, [H_FCT_DOMAIN]);
    hasher.finalize().into()
}

fn hash_g<P: Params>(hash_ek: &[u8], m: &[u8], salt: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, &hash_ek[..P::SEED_BYTES]);
    Digest::update(&mut hasher, &m[..P::VEC_K_SIZE_BYTES]);
    Digest::update(&mut hasher, &salt[..P::SALT_SIZE_BYTES]);
    Digest::update(&mut hasher, [G_FCT_DOMAIN]);
    hasher.finalize().into()
}

fn hash_j<P: Params>(hash_ek: &[u8], sigma: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, &hash_ek[..P::SEED_BYTES]);
    Digest::update(&mut hasher, &sigma[..P::VEC_K_SIZE_BYTES]);
    Digest::update(&mut hasher, &ct[..P::CT_BYTES]);
    Digest::update(&mut hasher, [J_FCT_DOMAIN]);
    hasher.finalize().into()
}

// ─── Per-variant keygen helpers ───

/// Seed expansion + call to `hqc::keygen`. Used by the per-variant modules.
pub(crate) fn keygen_from_seed<P: Params>(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut seed_kem = SecretVec::new(P::SEED_BYTES);
    prng_fill(seed, &mut seed_kem);

    let mut expanded = SecretVec::new(P::SEED_BYTES + P::VEC_K_SIZE_BYTES);
    xof_fill(&seed_kem, &mut expanded);
    let seed_pke = &expanded[..P::SEED_BYTES];
    let sigma = &expanded[P::SEED_BYTES..];

    let mut pk = vec![0u8; P::PK_BYTES];
    let mut sk = vec![0u8; P::SK_BYTES];
    hqc::keygen::<P>(&mut pk, &mut sk, seed_pke, sigma, &seed_kem);
    Ok((pk, sk))
}

// ─── Generic internal API (used by tests and per-variant modules) ───

/// Encapsulate: generate shared secret and ciphertext for a public key.
pub(crate) fn encaps<P: Params>(ct: &mut [u8], ss: &mut [u8; 32], pk: &[u8]) -> Result<(), Error> {
    if pk.len() != P::PK_BYTES {
        return Err(Error::InvalidKeyLength);
    }

    let mut m = SecretVec::new(P::VEC_K_SIZE_BYTES);
    getrandom::getrandom(&mut m).map_err(|_| Error::RngFailure)?;
    let mut salt = vec![0u8; P::SALT_SIZE_BYTES];
    getrandom::getrandom(&mut salt).map_err(|_| Error::RngFailure)?;

    let hash_ek = hash_h::<P>(pk);
    let k_theta = Zeroizing::new(hash_g::<P>(&hash_ek, &m, &salt));
    let theta = &k_theta[P::SS_BYTES..P::SS_BYTES + P::SEED_BYTES];

    let mut u = vec![0u64; P::VEC_N_SIZE_64];
    let mut v = vec![0u64; P::VEC_N1N2_SIZE_64];
    hqc::encrypt::<P>(&mut u, &mut v, &m, theta, pk);

    ss.copy_from_slice(&k_theta[..P::SS_BYTES]);

    parsing::hqc_ciphertext_to_string::<P>(ct, &u, &v, &salt);

    Ok(())
}

/// Deterministic encapsulate: derive m and salt from seed via SHAKE-256.
pub(crate) fn encaps_from_seed<P: Params>(
    ct: &mut [u8],
    ss: &mut [u8; 32],
    pk: &[u8],
    seed: &[u8],
) -> Result<(), Error> {
    if pk.len() != P::PK_BYTES {
        return Err(Error::InvalidKeyLength);
    }

    // Replay the KAT PRNG stream after keypair's seed_kem draw.
    let mut expanded = SecretVec::new(P::SEED_BYTES + P::VEC_K_SIZE_BYTES + P::SALT_SIZE_BYTES);
    let mut hash = Shake256::default();
    hash.update(seed);
    hash.update(&[PRNG_DOMAIN]);
    let mut reader = hash.finalize_xof();
    reader.read(&mut expanded);

    let m = &expanded[P::SEED_BYTES..P::SEED_BYTES + P::VEC_K_SIZE_BYTES];
    let salt = &expanded[P::SEED_BYTES + P::VEC_K_SIZE_BYTES..];

    let hash_ek = hash_h::<P>(pk);
    let k_theta = Zeroizing::new(hash_g::<P>(&hash_ek, m, salt));
    let theta = &k_theta[P::SS_BYTES..P::SS_BYTES + P::SEED_BYTES];

    let mut u = vec![0u64; P::VEC_N_SIZE_64];
    let mut v = vec![0u64; P::VEC_N1N2_SIZE_64];
    hqc::encrypt::<P>(&mut u, &mut v, m, theta, pk);

    ss.copy_from_slice(&k_theta[..P::SS_BYTES]);

    parsing::hqc_ciphertext_to_string::<P>(ct, &u, &v, salt);

    Ok(())
}

/// Decapsulate: recover shared secret from ciphertext using secret key.
pub(crate) fn decaps<P: Params>(ss: &mut [u8; 32], ct: &[u8], sk: &[u8]) -> Result<(), Error> {
    if ct.len() != P::CT_BYTES {
        return Err(Error::InvalidCiphertextLength);
    }
    if sk.len() != P::SK_BYTES {
        return Err(Error::InvalidSecretKeyLength);
    }

    let mut u = vec![0u64; P::VEC_N_SIZE_64];
    let mut v = vec![0u64; P::VEC_N1N2_SIZE_64];
    let mut salt = vec![0u8; P::SALT_SIZE_BYTES];
    parsing::hqc_ciphertext_from_string::<P>(&mut u, &mut v, &mut salt, ct);

    let mut m = SecretVec::new(P::VEC_K_SIZE_BYTES);
    let mut sigma = SecretVec::new(P::VEC_K_SIZE_BYTES);
    hqc::decrypt::<P>(&mut m, &u, &v, sk);

    let pk = &sk[..P::PK_BYTES];
    let sigma_off = P::PK_BYTES + P::SEED_BYTES;
    sigma.copy_from_slice(&sk[sigma_off..sigma_off + P::VEC_K_SIZE_BYTES]);

    let hash_ek = hash_h::<P>(pk);
    let k_theta_prime = Zeroizing::new(hash_g::<P>(&hash_ek, &m, &salt));
    let theta = &k_theta_prime[P::SS_BYTES..P::SS_BYTES + P::SEED_BYTES];

    let mut u2 = vec![0u64; P::VEC_N_SIZE_64];
    let mut v2 = vec![0u64; P::VEC_N1N2_SIZE_64];
    hqc::encrypt::<P>(&mut u2, &mut v2, &m, theta, pk);

    let u_bytes = &parsing::to_bytes(&u)[..P::VEC_N_SIZE_BYTES];
    let u2_bytes = &parsing::to_bytes(&u2)[..P::VEC_N_SIZE_BYTES];
    let u_match = u_bytes.ct_eq(u2_bytes);
    let v_bytes = &parsing::to_bytes(&v)[..P::VEC_N1N2_SIZE_BYTES];
    let v2_bytes = &parsing::to_bytes(&v2)[..P::VEC_N1N2_SIZE_BYTES];
    let v_match = v_bytes.ct_eq(v2_bytes);
    let success = u_match & v_match;

    let k_bar = Zeroizing::new(hash_j::<P>(&hash_ek, &sigma, ct));
    for i in 0..P::SS_BYTES {
        ss[i] = u8::conditional_select(&k_bar[i], &k_theta_prime[i], success);
    }

    Ok(())
}
