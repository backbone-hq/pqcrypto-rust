use crate::poly::Poly;
use sha3::{digest::ExtendableOutput, digest::Update, digest::XofReader, Shake256};

pub(crate) fn sample_poly_eta(poly: &mut Poly, seed: &[u8], nonce: u16, eta: usize) {
    let mut shake = Shake256::default();
    shake.update(seed);
    shake.update(&[(nonce & 0xFF) as u8, ((nonce >> 8) & 0xFF) as u8]);
    let mut reader = shake.finalize_xof();
    let mut i = 0;
    while i < 256 {
        let mut buf = [0u8; 1];
        reader.read(&mut buf);
        let x = i32::from(buf[0]);
        let t0 = x & 0x0F;
        let t1 = (x >> 4) & 0x0F;
        if eta == 2 {
            if t0 < 15 {
                let v = t0 - ((205 * t0) >> 10) * 5;
                poly.coeffs[i] = 2 - v;
                i += 1;
            }
            if i < 256 && t1 < 15 {
                let v = t1 - ((205 * t1) >> 10) * 5;
                poly.coeffs[i] = 2 - v;
                i += 1;
            }
        } else {
            if t0 < 9 {
                poly.coeffs[i] = 4 - t0;
                i += 1;
            }
            if i < 256 && t1 < 9 {
                poly.coeffs[i] = 4 - t1;
                i += 1;
            }
        }
    }
}

pub(crate) fn sample_poly_gamma1(poly: &mut Poly, seed: &[u8], nonce: u16, gamma1: usize) {
    use sha3::digest::ExtendableOutput;
    let shake_rate = 136;
    let packed_len: usize = if gamma1 == (1 << 17) { 576 } else { 640 };
    let blocks = packed_len.div_ceil(shake_rate);
    let buf_len = blocks * shake_rate;
    let mut buf = [0u8; 680];
    let buf = &mut buf[..buf_len];
    let mut shake = Shake256::default();
    shake.update(seed);
    shake.update(&[(nonce & 0xFF) as u8, ((nonce >> 8) & 0xFF) as u8]);
    let mut reader = shake.finalize_xof();
    reader.read(buf);
    if gamma1 == (1 << 17) {
        let mask = 0x3FFFF;
        let gamma1i = 1 << 17;
        for i in 0..64 {
            let off = 9 * i;
            let c0 = (i32::from(buf[off])
                | (i32::from(buf[off + 1]) << 8)
                | (i32::from(buf[off + 2]) << 16))
                & mask;
            let c1 = ((i32::from(buf[off + 2]) >> 2)
                | (i32::from(buf[off + 3]) << 6)
                | (i32::from(buf[off + 4]) << 14))
                & mask;
            let c2 = ((i32::from(buf[off + 4]) >> 4)
                | (i32::from(buf[off + 5]) << 4)
                | (i32::from(buf[off + 6]) << 12))
                & mask;
            let c3 = ((i32::from(buf[off + 6]) >> 6)
                | (i32::from(buf[off + 7]) << 2)
                | (i32::from(buf[off + 8]) << 10))
                & mask;
            poly.coeffs[4 * i] = gamma1i - c0;
            poly.coeffs[4 * i + 1] = gamma1i - c1;
            poly.coeffs[4 * i + 2] = gamma1i - c2;
            poly.coeffs[4 * i + 3] = gamma1i - c3;
        }
    } else {
        let mask = 0xFFFFF;
        let gamma1i = 1 << 19;
        for i in 0..128 {
            let off = 5 * i;
            let c0 = (i32::from(buf[off])
                | (i32::from(buf[off + 1]) << 8)
                | (i32::from(buf[off + 2]) << 16))
                & mask;
            let c1 = (i32::from(buf[off + 2]) >> 4)
                | (i32::from(buf[off + 3]) << 4)
                | (i32::from(buf[off + 4]) << 12);
            poly.coeffs[2 * i] = gamma1i - c0;
            poly.coeffs[2 * i + 1] = gamma1i - c1;
        }
    }
}

pub(crate) fn sample_poly_challenge(poly: &mut Poly, seed: &[u8], tau: usize) {
    let mut shake = Shake256::default();
    shake.update(seed);
    let mut reader = shake.finalize_xof();

    let mut buf = [0u8; 168];
    reader.read(&mut buf);

    let mut signs = 0u64;
    for i in 0..8 {
        signs |= u64::from(buf[i]) << (8 * i);
    }
    let mut pos = 8;

    poly.coeffs.fill(0);

    for i in (256 - tau)..256 {
        let b;
        loop {
            if pos >= 168 {
                reader.read(&mut buf);
                pos = 0;
            }
            let byte = buf[pos];
            pos += 1;
            if (byte as usize) <= i {
                b = byte as usize;
                break;
            }
        }

        poly.coeffs[i] = poly.coeffs[b];
        poly.coeffs[b] = if (signs & 1) == 0 { 1 } else { -1 };
        signs >>= 1;
    }
}
