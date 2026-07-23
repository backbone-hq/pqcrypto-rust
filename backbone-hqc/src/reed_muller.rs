//! Reed-Muller code RM(1,7) — encode and decode via fast Hadamard transform.
//! The RM(1,7) code encodes 8 bits into 128 bits, repeated MULTIPLICITY times.
use crate::params::*;

fn encode_byte(cword: &mut [u64], message: u8) {
    let mut first = if (message >> 7) & 1 != 0 {
        0xFFFFFFFFu32
    } else {
        0
    };
    if message & 1 != 0 {
        first ^= 0xAAAAAAAA;
    }
    if (message >> 1) & 1 != 0 {
        first ^= 0xCCCCCCCC;
    }
    if (message >> 2) & 1 != 0 {
        first ^= 0xF0F0F0F0;
    }
    if (message >> 3) & 1 != 0 {
        first ^= 0xFF00FF00;
    }
    if (message >> 4) & 1 != 0 {
        first ^= 0xFFFF0000;
    }
    cword[0] = u64::from(first);

    if (message >> 5) & 1 != 0 {
        first ^= 0xFFFFFFFF;
    }
    cword[0] |= u64::from(first) << 32;
    if (message >> 6) & 1 != 0 {
        first ^= 0xFFFFFFFF;
    }
    cword[1] = u64::from(first) << 32;
    if (message >> 5) & 1 != 0 {
        first ^= 0xFFFFFFFF;
    }
    cword[1] |= u64::from(first);
}

/// The message has N1 bytes, each encoded into an RM(1,7) codeword repeated MULTIPLICITY times.
pub(crate) fn encode<P: Params>(cdw: &mut [u64], msg: &[u8]) {
    let mult = P::RM_MULTIPLICITY;
    for i in 0..P::VEC_N1_SIZE_BYTES {
        let base = 2 * i * mult;
        encode_byte(&mut cdw[base..base + 2], msg[i]);
        for copy in 1..mult {
            let src = base;
            let dst = base + 2 * copy;
            cdw[dst] = cdw[src];
            cdw[dst + 1] = cdw[src + 1];
        }
    }
}

/// Hadamard transform matching the C reference.
/// 7 passes, each pairing 64 pairs: `dst[i] = src[2*i] + src[2*i+1]`, `dst[i+64] = src[2*i] - src[2*i+1]`.
/// Uses u16 (unsigned) matching C semantics.
fn hadamard(src: &mut [u16; 128], dst: &mut [u16; 128]) {
    let mut p1: [u16; 128] = *src;
    let mut p2: [u16; 128] = [0; 128];
    for _pass in 0..7 {
        for i in 0..64 {
            p2[i] = p1[2 * i].wrapping_add(p1[2 * i + 1]);
            p2[i + 64] = p1[2 * i].wrapping_sub(p1[2 * i + 1]);
        }
        core::mem::swap(&mut p1, &mut p2);
    }
    *dst = p1;
}

/// Expand codeword and sum repetitions (matching C reference).
fn expand_and_sum(expanded: &mut [u16; 128], cdw: &[u64], mult: usize) {
    for part in 0..2 {
        for bit in 0..64 {
            expanded[part * 64 + bit] = ((cdw[part] >> bit) & 1) as u16;
        }
    }
    for copy in 1..mult {
        for part in 0..2 {
            for bit in 0..64 {
                expanded[part * 64 + bit] += ((cdw[2 * copy + part] >> bit) & 1) as u16;
            }
        }
    }
}

/// Find the location of the highest value (matching C reference).
/// Sets bit 7 if the peak is positive.
fn find_peaks(transform: &[u16; 128]) -> u8 {
    let mut peak_abs: u16 = 0;
    let mut peak: u16 = 0;
    let mut pos: u16 = 0;
    for i in 0..128u16 {
        let t = transform[i as usize];
        let sign_ext = 0u16.wrapping_sub(t >> 15);
        let abs = t ^ (sign_ext & (t ^ (0u16.wrapping_sub(t))));
        let mask = 0u16.wrapping_sub(((peak_abs.wrapping_sub(abs)) >> 15) & 1);
        peak ^= mask & (peak ^ t);
        pos ^= mask & (pos ^ i);
        peak_abs ^= mask & (peak_abs ^ abs);
    }
    pos |= 128 & ((peak >> 15).wrapping_sub(1));
    // pos is 0..=127 (index into 128-element array), always fits in u8
    pos.try_into().expect("pos fits in return type")
}

pub(crate) fn decode<P: Params>(msg: &mut [u8], cdw: &[u64]) {
    let mult = P::RM_MULTIPLICITY;
    for i in 0..P::VEC_N1_SIZE_BYTES {
        let base = 2 * i * mult;
        let mut expanded = [0u16; 128];
        let mut transform = [0u16; 128];
        expand_and_sum(&mut expanded, &cdw[base..], mult);
        hadamard(&mut expanded, &mut transform);
        // mult is a small constant (RM_MULTIPLICITY = 3 or 8), fits in u16
        let mult_u16: u16 = mult.try_into().expect("mult fits in u16");
        transform[0] = transform[0].wrapping_sub(64 * mult_u16);
        msg[i] = find_peaks(&transform);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Hqc128;

    #[test]
    fn test_rm_roundtrip_all_bytes() {
        let mut enc = [0u64; 276];
        let mut dec = [0u8; 46];
        for byte in [0x00u8, 0xFF, 0x01, 0x80, 0x42, 0xAB, 0x55, 0xAA, 0x7F, 0x81] {
            let mut msg = [0u8; 46];
            msg[0] = byte;
            encode::<Hqc128>(&mut enc, &msg);
            decode::<Hqc128>(&mut dec, &enc);
            assert_eq!(dec[0], byte, "RM roundtrip failed for byte {:02x}", byte);
        }
    }

    #[test]
    fn test_rm_roundtrip_full() {
        let mut msg = [0u8; 46];
        for i in 0..46 {
            msg[i] = (i * 7 + 3) as u8;
        }
        let mut enc = [0u64; 276];
        encode::<Hqc128>(&mut enc, &msg);
        let mut dec = [0u8; 46];
        decode::<Hqc128>(&mut dec, &enc);
        assert_eq!(dec.as_slice(), msg.as_slice(), "RM full roundtrip failed");
    }
}
