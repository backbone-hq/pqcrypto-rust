//! Concatenated codec: Reed-Solomon outer + Reed-Muller inner.
//!
//! Encodes and decodes messages using a two-layer concatenated code scheme:
//! RS systematic encoding followed by RM encoding (encode), and the reverse
//! decode pipeline: RM decode → RS decode.

use crate::params::Params;
use crate::{reed_muller, reed_solomon};
use alloc::vec;

pub(crate) fn encode<P: Params>(em: &mut [u64], m: &[u8]) {
    let mut tmp = vec![0u8; P::VEC_N1_SIZE_BYTES];
    reed_solomon::encode::<P>(&mut tmp, m);
    reed_muller::encode::<P>(em, &tmp);
}

pub(crate) fn decode<P: Params>(m: &mut [u8], em: &[u64]) {
    let mut tmp = vec![0u8; P::VEC_N1_SIZE_BYTES];
    reed_muller::decode::<P>(&mut tmp, em);
    let decoded = reed_solomon::decode::<P>(&mut tmp);
    m.copy_from_slice(&decoded);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Hqc128;

    #[test]
    fn test_codec_roundtrip_trace() {
        let msg = vec![0xABu8; Hqc128::K];
        let mut em = vec![0u64; Hqc128::VEC_N1N2_SIZE_64];
        encode::<Hqc128>(&mut em, &msg);
        let mut dec = vec![0u8; Hqc128::K];
        decode::<Hqc128>(&mut dec, &em);
        assert_eq!(dec, msg, "Full codec roundtrip failed");
    }

    #[test]
    fn test_concat_codec_trace() {
        let msg = vec![0xABu8; Hqc128::K];
        let mut rs_cdw = vec![0u8; Hqc128::N1];
        reed_solomon::encode::<Hqc128>(&mut rs_cdw, &msg);
        let mut rm_cdw = vec![0u64; Hqc128::VEC_N1N2_SIZE_64];
        reed_muller::encode::<Hqc128>(&mut rm_cdw, &rs_cdw);
        let mut rm_dec = vec![0u8; Hqc128::VEC_N1_SIZE_BYTES];
        reed_muller::decode::<Hqc128>(&mut rm_dec, &rm_cdw);
        let rm_ok = rm_dec == rs_cdw.as_slice();
        assert!(rm_ok, "RM decode failed");
        let rs_dec = reed_solomon::decode::<Hqc128>(&mut rm_dec);
        assert_eq!(*rs_dec, msg, "Concatenated codec roundtrip failed");
    }
}
