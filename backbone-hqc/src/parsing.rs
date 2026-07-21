//! Serialization: key/ciphertext to/from byte strings.
use crate::params::Params;
use alloc::vec;
use alloc::vec::Vec;

/// Load an array of u64 from little-endian bytes.
pub(crate) fn load8_arr(out: &mut [u64], inp: &[u8]) {
    let outlen = out.len();
    let inlen = inp.len();
    let mut i = 0;
    let mut j = 0;
    while i < outlen && j + 8 <= inlen {
        out[i] = u64::from_le_bytes([
            inp[j],
            inp[j + 1],
            inp[j + 2],
            inp[j + 3],
            inp[j + 4],
            inp[j + 5],
            inp[j + 6],
            inp[j + 7],
        ]);
        i += 1;
        j += 8;
    }
    if i < outlen && j < inlen {
        let remaining = inlen - j;
        let mut bytes = [0u8; 8];
        bytes[..remaining].copy_from_slice(&inp[j..]);
        out[i] = u64::from_le_bytes(bytes);
    }
}

/// Store an array of u64 to little-endian bytes.
pub(crate) fn store8_arr(out: &mut [u8], inp: &[u64]) {
    let outlen = out.len();
    let inlen = inp.len();
    let mut i = 0;
    let mut j = 0;
    while i < inlen && j + 8 <= outlen {
        let bytes = inp[i].to_le_bytes();
        out[j..j + 8].copy_from_slice(&bytes);
        i += 1;
        j += 8;
    }
    if i < inlen && j < outlen {
        let bytes = inp[i].to_le_bytes();
        let remaining = outlen - j;
        out[j..].copy_from_slice(&bytes[..remaining]);
    }
}

/// Convert u64 slice to bytes.
#[must_use]
pub(crate) fn to_bytes(v: &[u64]) -> Vec<u8> {
    let mut bytes = vec![0u8; v.len() * 8];
    store8_arr(&mut bytes, v);
    bytes
}

/// Serialize a KEM secret key.
/// Format: ek_pke || dk_pke || sigma || seed_kem
pub(crate) fn hqc_secret_key_to_string<P: Params>(
    sk: &mut [u8],
    ek_pke: &[u8],
    dk_pke: &[u8],
    sigma: &[u8],
    seed_kem: &[u8],
) {
    sk[..P::PK_BYTES].copy_from_slice(ek_pke);
    sk[P::PK_BYTES..P::PK_BYTES + P::SEED_BYTES].copy_from_slice(dk_pke);
    sk[P::PK_BYTES + P::SEED_BYTES..P::PK_BYTES + P::SEED_BYTES + P::VEC_K_SIZE_BYTES]
        .copy_from_slice(sigma);
    sk[P::PK_BYTES + P::SEED_BYTES + P::VEC_K_SIZE_BYTES..].copy_from_slice(seed_kem);
}

/// Serialize a public key.
/// Format: seed_ek || s (VEC_N_SIZE_BYTES)
pub(crate) fn hqc_public_key_to_string<P: Params>(pk: &mut [u8], seed_ek: &[u8], s: &[u64]) {
    pk[..P::SEED_BYTES].copy_from_slice(seed_ek);
    store8_arr(&mut pk[P::SEED_BYTES..], s);
}

/// Serialize a ciphertext.
/// Format: u (VEC_N_SIZE_BYTES) || v (VEC_N1N2_SIZE_BYTES) || salt (16)
pub(crate) fn hqc_ciphertext_to_string<P: Params>(
    ct: &mut [u8],
    u: &[u64],
    v: &[u64],
    salt: &[u8],
) {
    let u_bytes = P::VEC_N_SIZE_BYTES;
    let v_bytes = P::VEC_N1N2_SIZE_BYTES;
    store8_arr(&mut ct[..u_bytes], u);
    store8_arr(&mut ct[u_bytes..u_bytes + v_bytes], v);
    ct[u_bytes + v_bytes..].copy_from_slice(salt);
}

/// Deserialize a ciphertext.
pub(crate) fn hqc_ciphertext_from_string<P: Params>(
    u: &mut [u64],
    v: &mut [u64],
    salt: &mut [u8],
    ct: &[u8],
) {
    let u_bytes = P::VEC_N_SIZE_BYTES;
    let v_bytes = P::VEC_N1N2_SIZE_BYTES;
    load8_arr(u, &ct[..u_bytes]);
    load8_arr(v, &ct[u_bytes..u_bytes + v_bytes]);
    salt.copy_from_slice(&ct[u_bytes + v_bytes..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_store_roundtrip() {
        let input = [0x0123456789ABCDEFu64; 4];
        let mut bytes = vec![0u8; 32];
        store8_arr(&mut bytes, &input);
        let mut output = [0u64; 4];
        load8_arr(&mut output, &bytes);
        assert_eq!(input, output);
    }
}
