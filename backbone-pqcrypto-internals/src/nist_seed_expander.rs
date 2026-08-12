use crate::secret::SecretArray;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::Aes256;

fn increment_be(v: &mut [u8; 16]) {
    for byte in v.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

#[allow(missing_copy_implementations)]
pub struct NistSeedExpander {
    // Zeroizing wrappers: the DRBG key and counter are derived from the
    // secret keygen seed and must be wiped when the expander is dropped.
    key: SecretArray<u8, 32>,
    v: SecretArray<u8, 16>,
}

// Redacted Debug: the DRBG key/v are derived from the 48-byte keygen seed
// and must never be printed (the previous derived Debug leaked them).
impl core::fmt::Debug for NistSeedExpander {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NistSeedExpander").finish_non_exhaustive()
    }
}

impl NistSeedExpander {
    #[must_use]
    pub fn new(entropy_input: &[u8; 48]) -> Self {
        let mut state = Self {
            key: SecretArray::new(),
            v: SecretArray::new(),
        };
        state.update(Some(entropy_input));
        state
    }

    fn update(&mut self, provided: Option<&[u8; 48]>) {
        let cipher = Aes256::new_from_slice(self.key.as_ref()).expect("32-byte key");
        let mut temp = [0u8; 48];
        for block in temp.chunks_exact_mut(16) {
            increment_be(&mut self.v);
            let mut buf: aes::Block = (*self.v).into();
            cipher.encrypt_block_inout((&mut buf).into());
            block.copy_from_slice(&buf);
        }
        if let Some(p) = provided {
            for (t, x) in temp.iter_mut().zip(p.iter()) {
                *t ^= x;
            }
        }
        self.key.copy_from_slice(&temp[..32]);
        self.v.copy_from_slice(&temp[32..]);
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        let cipher = Aes256::new_from_slice(self.key.as_ref()).expect("32-byte key");
        let mut i = 0usize;
        while i < out.len() {
            increment_be(&mut self.v);
            let mut block: [u8; 16] = *self.v;
            cipher.encrypt_block((&mut block).into());
            let take = core::cmp::min(16, out.len() - i);
            out[i..i + take].copy_from_slice(&block[..take]);
            i += take;
        }
        self.update(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_nist_reference_vector() {
        let seed: [u8; 48] = [
            0x06, 0x15, 0x50, 0x23, 0x4D, 0x15, 0x8C, 0x5E, 0xC9, 0x55, 0x95, 0xFE, 0x04, 0xEF,
            0x7A, 0x25, 0x76, 0x7F, 0x2E, 0x24, 0xCC, 0x2B, 0xC4, 0x79, 0xD0, 0x9D, 0x86, 0xDC,
            0x9A, 0xBC, 0xFD, 0xE7, 0x05, 0x6A, 0x8C, 0x26, 0x6F, 0x9E, 0xF9, 0x7E, 0xD0, 0x85,
            0x41, 0xDB, 0xD2, 0xE1, 0xFF, 0xA1,
        ];
        let mut drbg = NistSeedExpander::new(&seed);
        let mut out = [0u8; 32];
        drbg.fill_bytes(&mut out);
        let expected = [
            0x7c, 0x99, 0x35, 0xa0, 0xb0, 0x76, 0x94, 0xaa, 0x0c, 0x6d, 0x10, 0xe4, 0xdb, 0x6b,
            0x1a, 0xdd, 0x2f, 0xd8, 0x1a, 0x25, 0xcc, 0xb1, 0x48, 0x03, 0x2d, 0xcd, 0x73, 0x99,
            0x36, 0x73, 0x7f, 0x2d,
        ];
        assert_eq!(out, expected);
    }
}
