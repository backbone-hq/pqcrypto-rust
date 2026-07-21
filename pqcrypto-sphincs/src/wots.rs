use crate::address::{Adrs, ADDR_TYPE_WOTS, ADDR_TYPE_WOTSPK, ADDR_TYPE_WOTSPRF};
use crate::hash::Hash;
use pqcrypto_utils::secret::SecretArray;

const WOTS_W: u32 = 16;
const WOTS_LOGW: u32 = 4;

fn base_w(output: &mut [u32], input: &[u8]) {
    let mut in_pos = 0;
    let mut total = 0u8;
    let mut bits = 0;

    for out_val in output.iter_mut() {
        if bits == 0 {
            total = input[in_pos];
            in_pos += 1;
            bits = 8;
        }
        bits -= WOTS_LOGW;
        *out_val = (u32::from(total) >> bits) & (WOTS_W - 1);
    }
}

fn wots_checksum<H: Hash>(csum_base_w: &mut [u32], msg_base_w: &[u32]) {
    let len1 = H::N * 8 / (WOTS_LOGW as usize);
    let len2 = 3;
    let csum_bytes_len = (len2 * (WOTS_LOGW as usize)).div_ceil(8);

    let mut csum = 0u32;
    for i in 0..len1 {
        csum += (WOTS_W - 1) - msg_base_w[i];
    }

    csum <<=
        u32::try_from((8 - ((len2 * (WOTS_LOGW as usize)) % 8)) % 8).expect("shift fits in u32");

    let mut csum_bytes_arr = SecretArray::<u8, 4>::new();
    let csum_bytes = &mut csum_bytes_arr[..csum_bytes_len];
    crate::utils::ull_to_bytes(csum_bytes, u64::from(csum));
    base_w(csum_base_w, csum_bytes);
}

pub(crate) fn chain_lengths<H: Hash>(lengths: &mut [u32], msg: &[u8]) {
    let len1 = H::N * 8 / (WOTS_LOGW as usize);
    base_w(&mut lengths[..len1], msg);
    let (msg_part, csum_part) = lengths.split_at_mut(len1);
    wots_checksum::<H>(csum_part, msg_part);
}

pub(crate) fn wots_pk_from_sig<H: Hash>(
    pk: &mut [u8],
    sig: &[u8],
    msg: &[u8],
    pub_seed: &[u8],
    addr: &mut Adrs,
) {
    let n = H::N;
    let len1 = H::N * 8 / (WOTS_LOGW as usize);
    let wots_len = len1 + 3;

    let mut lengths_arr = SecretArray::<u32, 67>::new();
    let lengths = &mut lengths_arr[..wots_len];
    chain_lengths::<H>(lengths, msg);

    for i in 0..wots_len {
        addr.set_chain_addr::<H>(u32::try_from(i).expect("i fits in u32"));

        let start = lengths[i];
        let steps = (WOTS_W - 1) - lengths[i];
        let off = i * n;

        let mut buf = SecretArray::<u8, 32>::new();
        buf[..n].copy_from_slice(&sig[off..off + n]);

        for k in start..start + steps {
            if k >= WOTS_W {
                break;
            }
            addr.set_hash_addr::<H>(k);
            let mut tmp = SecretArray::<u8, 32>::new();
            H::thash(&mut tmp[..n], &buf[..n], 1, pub_seed, addr.as_bytes());
            buf[..n].copy_from_slice(&tmp[..n]);
        }

        pk[off..off + n].copy_from_slice(&buf[..n]);
    }
}

pub(crate) fn wots_gen_leafx1<H: Hash>(
    dest: &mut [u8],
    leaf_idx_val: u32,
    pub_seed: &[u8],
    sk_seed: &[u8],
    wots_sig: &mut [u8],
    wots_sign_leaf: u32,
    wots_steps: &[u32],
    addr: &mut Adrs,
    pk_buffer: &mut [u8],
) {
    let n = H::N;
    let len1 = H::N * 8 / (WOTS_LOGW as usize);
    let wots_len = len1 + 3;

    let wots_k_mask = if leaf_idx_val == wots_sign_leaf {
        0u32
    } else {
        !0u32
    };

    let mut leaf_addr = *addr;
    let mut pk_addr = *addr;
    leaf_addr.set_keypair_addr::<H>(leaf_idx_val);
    pk_addr.set_keypair_addr::<H>(leaf_idx_val);
    pk_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_WOTSPK);

    for i in 0..wots_len {
        let wots_k = wots_steps[i] | wots_k_mask;
        let off = i * n;

        leaf_addr.set_chain_addr::<H>(u32::try_from(i).expect("i fits in u32"));
        leaf_addr.set_hash_addr::<H>(0);
        leaf_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_WOTSPRF);

        H::prf_addr(
            &mut pk_buffer[off..off + n],
            pub_seed,
            sk_seed,
            leaf_addr.as_bytes(),
        );

        leaf_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_WOTS);

        for k in 0..WOTS_W {
            if k == wots_k {
                wots_sig[off..off + n].copy_from_slice(&pk_buffer[off..off + n]);
            }
            if k == WOTS_W - 1 {
                break;
            }
            leaf_addr.set_hash_addr::<H>(k);

            let mut tmp = SecretArray::<u8, 32>::new();
            H::thash(
                &mut tmp[..n],
                &pk_buffer[off..off + n],
                1,
                pub_seed,
                leaf_addr.as_bytes(),
            );
            pk_buffer[off..off + n].copy_from_slice(&tmp[..n]);
        }
    }

    H::thash(
        dest,
        &pk_buffer[..wots_len * n],
        wots_len,
        pub_seed,
        pk_addr.as_bytes(),
    );
}
