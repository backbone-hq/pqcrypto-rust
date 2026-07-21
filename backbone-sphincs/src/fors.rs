use crate::address::{Adrs, ADDR_TYPE_FORSPK, ADDR_TYPE_FORSPRF, ADDR_TYPE_FORSTREE};
use crate::hash::Hash;
use crate::utils::{compute_root, treehashx1};
use backbone_pqcrypto_internals::secret::SecretArray;

fn message_to_indices(indices: &mut [u32], m: &[u8], fors_height: usize, fors_trees: usize) {
    let mut offset = 0;
    for i in 0..fors_trees {
        let mut val = 0u32;
        for j in 0..fors_height {
            let bit = u32::from((m[offset >> 3] >> (offset & 7)) & 1);
            val ^= bit << j;
            offset += 1;
        }
        indices[i] = val;
    }
}

pub(crate) fn fors_sign<H: Hash>(
    sig: &mut [u8],
    pk: &mut [u8],
    m: &[u8],
    pub_seed: &[u8],
    sk_seed: &[u8],
    fors_addr: &Adrs,
) {
    let n = H::N;
    let k = H::K;
    let fors_height = H::LOG_T;

    let mut indices_arr = SecretArray::<u32, 35>::new();
    let indices = &mut indices_arr[..k];
    let mut roots_arr = SecretArray::<u8, 1120>::new();
    let roots = &mut roots_arr[..k * n];
    let mut fors_tree_addr = Adrs::new();
    let mut fors_leaf_addr = Adrs::new();
    let mut fors_pk_addr = Adrs::new();

    fors_tree_addr.copy_keypair::<H>(fors_addr);
    fors_leaf_addr.copy_keypair::<H>(fors_addr);
    fors_pk_addr.copy_keypair::<H>(fors_addr);
    fors_pk_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_FORSPK);

    message_to_indices(indices, m, fors_height, k);

    let mut sig_pos = 0;
    for i in 0..k {
        let idx_offset = u32::try_from(i).expect("i fits in u32") * (1 << fors_height);

        fors_tree_addr.set_tree_height::<H>(0);
        fors_tree_addr.set_tree_index::<H>(indices[i] + idx_offset);
        fors_tree_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_FORSPRF);

        H::prf_addr(
            &mut sig[sig_pos..sig_pos + n],
            pub_seed,
            sk_seed,
            fors_tree_addr.as_bytes(),
        );
        fors_tree_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_FORSTREE);
        sig_pos += n;

        let mut gen_leaf = |leaf: &mut [u8], addr_idx: u32, _ps: &[u8]| {
            fors_leaf_addr.set_tree_index::<H>(addr_idx);
            fors_leaf_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_FORSPRF);
            H::prf_addr(leaf, pub_seed, sk_seed, fors_leaf_addr.as_bytes());
            fors_leaf_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_FORSTREE);
            let mut tmp = SecretArray::<u8, 32>::new();
            H::thash(&mut tmp[..n], leaf, 1, pub_seed, fors_leaf_addr.as_bytes());
            leaf.copy_from_slice(&tmp[..n]);
        };

        treehashx1::<H>(
            &mut roots[i * n..(i + 1) * n],
            &mut sig[sig_pos..],
            indices[i],
            idx_offset,
            u32::try_from(fors_height).expect("fors_height fits in u32"),
            pub_seed,
            &mut fors_tree_addr,
            &mut gen_leaf,
        );

        sig_pos += n * fors_height;
    }

    H::thash(pk, roots, k, pub_seed, fors_pk_addr.as_bytes());
}

pub(crate) fn fors_pk_from_sig<H: Hash>(
    pk: &mut [u8],
    sig: &[u8],
    m: &[u8],
    pub_seed: &[u8],
    fors_addr: &Adrs,
) {
    let n = H::N;
    let k = H::K;
    let fors_height = H::LOG_T;

    let mut indices_arr = SecretArray::<u32, 35>::new();
    let indices = &mut indices_arr[..k];
    let mut roots_arr = SecretArray::<u8, 1120>::new();
    let roots = &mut roots_arr[..k * n];
    let mut fors_tree_addr = Adrs::new();
    let mut fors_pk_addr = Adrs::new();

    fors_tree_addr.copy_keypair::<H>(fors_addr);
    fors_pk_addr.copy_keypair::<H>(fors_addr);
    fors_tree_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_FORSTREE);
    fors_pk_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_FORSPK);

    message_to_indices(indices, m, fors_height, k);

    let mut sig_pos = 0;
    for i in 0..k {
        let idx_offset = u32::try_from(i).expect("i fits in u32") * (1 << fors_height);

        fors_tree_addr.set_tree_height::<H>(0);
        fors_tree_addr.set_tree_index::<H>(indices[i] + idx_offset);

        let mut leaf = SecretArray::<u8, 32>::new();
        H::thash(
            &mut leaf[..n],
            &sig[sig_pos..sig_pos + n],
            1,
            pub_seed,
            fors_tree_addr.as_bytes(),
        );
        sig_pos += n;

        let auth_path_len = n * fors_height;
        compute_root::<H>(
            &mut roots[i * n..(i + 1) * n],
            &leaf[..n],
            indices[i],
            idx_offset,
            &sig[sig_pos..sig_pos + auth_path_len],
            pub_seed,
            &mut fors_tree_addr,
        );
        sig_pos += auth_path_len;
    }

    H::thash(pk, roots, k, pub_seed, fors_pk_addr.as_bytes());
}
