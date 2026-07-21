// Shared types, re-exports, and utility functions for all McEliece variants

pub(crate) use sha3::digest::{ExtendableOutput, Update, XofReader};

pub(crate) type Gf = u16;
pub(crate) type Vec64 = u64;

pub(crate) fn vec_setbits(bit: u64) -> Vec64 {
    0u64.wrapping_sub(bit)
}
