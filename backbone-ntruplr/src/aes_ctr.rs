//! AES-256-CTR stream cipher wrapper.
//! Used by NTRUPLR for deterministic pseudorandom generation
//! in rq_fromseed and small_seeded_weightw.
//!
//! Reference: crypto_stream_aes256ctr (eSTREAM / NaCl)
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;

type Aes256Ctr = Ctr128BE<Aes256>;

/// Generate `out.len()` bytes of AES256-CTR keystream with the given key
/// and a zero nonce (16 bytes of 0x00), matching the reference implementation.
#[cfg(test)]
pub(crate) fn aes256_ctr(key: &[u8; 32], out: &mut [u8]) {
    aes256_ctr_fill(key, out);
}

/// Generate `out.len()` bytes of AES256-CTR keystream, writing directly
/// (in-place keystream generation, avoids the zero-buffer copy on some backends)
pub(crate) fn aes256_ctr_fill(key: &[u8; 32], out: &mut [u8]) {
    let nonce = [0u8; 16];
    let mut cipher = Aes256Ctr::new(key.into(), &nonce.into());
    cipher.apply_keystream(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_ctr_deterministic() {
        let key = [0x42u8; 32];
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        aes256_ctr(&key, &mut out1);
        aes256_ctr(&key, &mut out2);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_aes256_ctr_nonzero() {
        let key = [0x42u8; 32];
        let mut out = [0u8; 64];
        aes256_ctr(&key, &mut out);
        assert!(out.iter().any(|&b| b != 0));
    }
}
