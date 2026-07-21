use crate::address::{Adrs, ADDR_TYPE_HASHTREE, ADDR_TYPE_WOTSPK};
use crate::hash::Hash;
use crate::utils::treehashx1;
use crate::wots::{chain_lengths, wots_gen_leafx1};
use pqcrypto_utils::secret::SecretArray;

pub(crate) fn merkle_sign<H: Hash>(
    sig: &mut [u8],
    root: &mut [u8],
    pub_seed: &[u8],
    sk_seed: &[u8],
    wots_addr: &Adrs,
    tree_addr: &mut Adrs,
    idx_leaf: u32,
) {
    let n = H::N;

    let auth_path_len = H::TREE_H * n;
    let (wots_sig, auth_path) = sig.split_at_mut(H::WOTS_BYTES);

    let mut wots_steps_arr = SecretArray::<u32, 67>::new();
    let wots_steps = &mut wots_steps_arr[..H::WOTS_LEN];
    chain_lengths::<H>(wots_steps, root);

    tree_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_HASHTREE);

    let mut leaf_addr = Adrs::new();
    let mut pk_addr = Adrs::new();
    leaf_addr.copy_subtree::<H>(wots_addr);
    pk_addr.copy_subtree::<H>(wots_addr);
    pk_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_WOTSPK);

    let sig_len = H::WOTS_BYTES;

    // Allocate WOTS scratch buffer once, reuse for all leaves
    let wots_len = H::WOTS_LEN;
    let mut pk_buffer_arr = SecretArray::<u8, 2144>::new();
    let pk_buffer = &mut pk_buffer_arr[..wots_len * n];

    let mut gen_leaf = |dest: &mut [u8], leaf_idx_val: u32, ps: &[u8]| {
        let wots_sig_slice = &mut wots_sig[..sig_len];
        wots_gen_leafx1::<H>(
            dest,
            leaf_idx_val,
            ps,
            sk_seed,
            wots_sig_slice,
            idx_leaf,
            wots_steps,
            &mut leaf_addr,
            pk_buffer,
        );
    };

    treehashx1::<H>(
        root,
        &mut auth_path[..auth_path_len],
        idx_leaf,
        0,
        u32::try_from(H::TREE_H).expect("TREE_H fits in u32"),
        pub_seed,
        tree_addr,
        &mut gen_leaf,
    );
}

pub(crate) fn merkle_gen_root<H: Hash>(root: &mut [u8], pub_seed: &[u8], sk_seed: &[u8]) {
    let n = H::N;
    let mut auth_path_arr = SecretArray::<u8, 2432>::new();
    let auth_path = &mut auth_path_arr[..H::WOTS_BYTES + H::TREE_H * n];

    let mut top_tree_addr = Adrs::new();
    let mut wots_addr = Adrs::new();

    top_tree_addr.set_layer_addr::<H>(u32::try_from(H::D - 1).expect("D-1 fits in u32"));
    wots_addr.set_layer_addr::<H>(u32::try_from(H::D - 1).expect("D-1 fits in u32"));

    merkle_sign::<H>(
        auth_path,
        root,
        pub_seed,
        sk_seed,
        &wots_addr,
        &mut top_tree_addr,
        !0u32,
    );
}
