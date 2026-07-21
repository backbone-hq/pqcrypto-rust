use crate::address::Adrs;
use crate::hash::Hash;
use backbone_pqcrypto_internals::secret::SecretArray;

pub(crate) fn ull_to_bytes(out: &mut [u8], val: u64) {
    let bytes = val.to_be_bytes();
    let start = bytes.len() - out.len().min(bytes.len());
    out.copy_from_slice(&bytes[start..]);
}

pub(crate) fn compute_root<H: Hash>(
    root: &mut [u8],
    leaf: &[u8],
    mut leaf_idx: u32,
    mut idx_offset: u32,
    auth_path: &[u8],
    pub_seed: &[u8],
    addr: &mut Adrs,
) {
    let n = H::N;
    let tree_height = u32::try_from(auth_path.len() / n).expect("tree_height fits in u32");
    let mut buf = SecretArray::<u8, 64>::new();

    if leaf_idx & 1 == 1 {
        buf[..n].copy_from_slice(&auth_path[..n]);
        buf[n..2 * n].copy_from_slice(leaf);
    } else {
        buf[..n].copy_from_slice(leaf);
        buf[n..2 * n].copy_from_slice(&auth_path[..n]);
    }

    let mut auth = &auth_path[n..];

    for i in 0..tree_height - 1 {
        leaf_idx >>= 1;
        idx_offset >>= 1;

        addr.set_tree_height::<H>(i + 1);
        addr.set_tree_index::<H>(leaf_idx + idx_offset);

        if leaf_idx & 1 == 0 {
            let mut tmp = SecretArray::<u8, 32>::new();
            H::thash(&mut tmp[..n], &buf[..2 * n], 2, pub_seed, addr.as_bytes());
            buf[..n].copy_from_slice(&tmp[..n]);
            buf[n..2 * n].copy_from_slice(&auth[..n]);
        } else {
            let mut tmp = SecretArray::<u8, 32>::new();
            H::thash(&mut tmp[..n], &buf[..2 * n], 2, pub_seed, addr.as_bytes());
            buf[n..2 * n].copy_from_slice(&tmp[..n]);
            buf[..n].copy_from_slice(&auth[..n]);
        }
        auth = &auth[n..];
    }

    leaf_idx >>= 1;
    idx_offset >>= 1;
    addr.set_tree_height::<H>(tree_height);
    addr.set_tree_index::<H>(leaf_idx + idx_offset);
    H::thash(root, &buf[..2 * n], 2, pub_seed, addr.as_bytes());
}

pub(crate) fn treehashx1<H: Hash>(
    root: &mut [u8],
    auth_path: &mut [u8],
    leaf_idx: u32,
    idx_offset: u32,
    tree_height: u32,
    pub_seed: &[u8],
    addr: &mut Adrs,
    gen_leaf: &mut impl FnMut(&mut [u8], u32, &[u8]),
) {
    let n = H::N;
    let max_idx = (1u32 << tree_height) - 1;

    let mut stack_arr = SecretArray::<u8, 2048>::new();
    let stack = &mut stack_arr[..(tree_height as usize) * n];
    let mut current = SecretArray::<u8, 64>::new();

    for idx in 0..=max_idx {
        gen_leaf(&mut current[n..2 * n], idx + idx_offset, pub_seed);

        let mut h = 0u32;
        let mut internal_idx = idx;
        let mut internal_leaf = leaf_idx;
        let mut internal_offset = idx_offset;

        loop {
            if h == tree_height {
                root.copy_from_slice(&current[n..n + n]);
                return;
            }

            if (internal_idx ^ internal_leaf) == 1 {
                let off = (h as usize) * n;
                auth_path[off..off + n].copy_from_slice(&current[n..n + n]);
            }

            if (internal_idx & 1) == 0 && idx < max_idx {
                break;
            }

            internal_offset >>= 1;
            let tree_idx = (internal_idx / 2) + internal_offset;
            addr.set_tree_height::<H>(h + 1);
            addr.set_tree_index::<H>(tree_idx);

            current[..n].copy_from_slice(&stack[(h as usize) * n..(h as usize + 1) * n]);

            let mut tmp = SecretArray::<u8, 32>::new();
            H::thash(
                &mut tmp[..n],
                &current[..2 * n],
                2,
                pub_seed,
                addr.as_bytes(),
            );
            current[n..2 * n].copy_from_slice(&tmp[..n]);

            h += 1;
            internal_idx >>= 1;
            internal_leaf >>= 1;
        }

        stack[(h as usize) * n..(h as usize + 1) * n].copy_from_slice(&current[n..n + n]);
    }
}
