use crate::address::{Adrs, ADDR_TYPE_HASHTREE, ADDR_TYPE_WOTS, ADDR_TYPE_WOTSPK};
use crate::error::Error;
use crate::fors::{fors_pk_from_sig, fors_sign};
use crate::hash::Hash;
use crate::merkle::merkle_gen_root;
use crate::merkle::merkle_sign;
use crate::utils::compute_root;
use crate::wots::wots_pk_from_sig;
use alloc::vec;
use alloc::vec::Vec;
use pqcrypto_utils::secret::{SecretArray, SecretVec};
use sha3::{digest::ExtendableOutput, digest::Update, digest::XofReader, Shake256};

#[must_use]
pub(crate) fn keygen<H: Hash>(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let seed_storage;
    let seed = if seed.len() == H::SEED_BYTES {
        seed
    } else {
        seed_storage = expand_seed::<H>(seed);
        &*seed_storage
    };

    let n = H::N;
    let mut pk = vec![0u8; H::PK_BYTES];
    let mut sk = vec![0u8; H::SK_BYTES];

    sk[..H::SEED_BYTES].copy_from_slice(seed);
    pk[..n].copy_from_slice(&sk[2 * n..3 * n]);

    let pub_seed = &pk[..n];
    let (sk_prefix, sk_tail) = sk.split_at_mut(n);
    let sk_seed = &sk_prefix[..n];

    merkle_gen_root::<H>(&mut sk_tail[2 * n..3 * n], pub_seed, sk_seed);

    pk[n..2 * n].copy_from_slice(&sk[3 * n..4 * n]);

    (pk, sk)
}

pub(crate) fn keygen_checked<H: Hash>(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if seed.len() != H::SEED_BYTES {
        return Err(Error::InvalidSeedLength);
    }
    Ok(keygen::<H>(seed))
}

fn expand_seed<H: Hash>(seed: &[u8]) -> SecretVec<u8> {
    let mut out = SecretVec::<u8>::new(H::SEED_BYTES);
    let mut shake = Shake256::default();
    shake.update(seed);
    let mut reader = shake.finalize_xof();
    reader.read(&mut out);
    out
}

pub(crate) fn sign<H: Hash>(sk: &[u8], msg: &[u8], optrand: &[u8]) -> Result<Vec<u8>, Error> {
    if sk.len() != H::SK_BYTES {
        return Err(Error::InvalidSecretKeyLength);
    }
    if optrand.len() != H::N {
        return Err(Error::InvalidSeedLength);
    }

    let n = H::N;
    let mut sig = vec![0u8; H::SIG_BYTES];

    let sk_seed = &sk[..n];
    let sk_prf = &sk[n..2 * n];
    let pk_secret = &sk[2 * n..4 * n];
    let pub_seed = &pk_secret[..n];
    let sig_r = &mut sig[..n];

    H::gen_message_random(sig_r, sk_prf, optrand, msg);

    let fors_msg_bytes = (H::LOG_T * H::K).div_ceil(8);
    let mut mhash_arr = SecretArray::<u8, 64>::new();
    let mhash = &mut mhash_arr[..fors_msg_bytes];
    let mut tree = 0u64;
    let mut idx_leaf = 0u32;

    H::hash_message(mhash, &mut tree, &mut idx_leaf, sig_r, pk_secret, msg);

    let mut sig_pos = n;

    let mut wots_addr = Adrs::new();
    let mut tree_addr = Adrs::new();

    wots_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_WOTS);
    tree_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_HASHTREE);

    wots_addr.set_tree_addr::<H>(tree);
    wots_addr.set_keypair_addr::<H>(idx_leaf);

    let mut root_arr = SecretArray::<u8, 32>::new();
    let root = &mut root_arr[..n];
    fors_sign::<H>(
        &mut sig[sig_pos..],
        root,
        mhash,
        pub_seed,
        sk_seed,
        &wots_addr,
    );
    sig_pos += H::FORS_BYTES;

    for i in 0..H::D {
        let i_u32 = u32::try_from(i).expect("i fits in u32");
        tree_addr.set_layer_addr::<H>(i_u32);
        tree_addr.set_tree_addr::<H>(tree);

        wots_addr.copy_subtree::<H>(&tree_addr);
        wots_addr.set_keypair_addr::<H>(idx_leaf);

        merkle_sign::<H>(
            &mut sig[sig_pos..],
            root,
            pub_seed,
            sk_seed,
            &wots_addr,
            &mut tree_addr,
            idx_leaf,
        );
        sig_pos += H::WOTS_BYTES + H::TREE_H * n;

        idx_leaf = u32::try_from(tree & ((1u64 << H::TREE_H) - 1)).expect("value fits in u32");
        tree >>= H::TREE_H;
    }

    Ok(sig)
}

#[must_use]
pub(crate) fn verify<H: Hash>(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if sig.len() != H::SIG_BYTES {
        return false;
    }
    if pk.len() != H::PK_BYTES {
        return false;
    }

    let n = H::N;
    let sig_bytes = sig;
    let pub_seed = &pk[..n];
    let pub_root = &pk[n..2 * n];

    let fors_msg_bytes = (H::LOG_T * H::K).div_ceil(8);
    let mut mhash_arr = SecretArray::<u8, 64>::new();
    let mhash = &mut mhash_arr[..fors_msg_bytes];
    let mut tree = 0u64;
    let mut leaf_idx = 0u32;

    H::hash_message(mhash, &mut tree, &mut leaf_idx, &sig_bytes[..n], pk, msg);

    let mut sig_pos = n;
    let mut root_arr = SecretArray::<u8, 32>::new();
    let root = &mut root_arr[..n];

    let mut wots_addr = Adrs::new();
    let mut tree_addr = Adrs::new();
    let mut wots_pk_addr = Adrs::new();

    wots_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_WOTS);
    tree_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_HASHTREE);
    wots_pk_addr.set_type(H::OFFSET_TYPE, ADDR_TYPE_WOTSPK);

    wots_addr.set_tree_addr::<H>(tree);
    wots_addr.set_keypair_addr::<H>(leaf_idx);

    fors_pk_from_sig::<H>(root, &sig_bytes[sig_pos..], mhash, pub_seed, &wots_addr);
    sig_pos += H::FORS_BYTES;

    let mut wots_pk_buf = SecretArray::<u8, 2144>::new();
    for i in 0..H::D {
        let i_u32 = u32::try_from(i).expect("i fits in u32");
        tree_addr.set_layer_addr::<H>(i_u32);
        tree_addr.set_tree_addr::<H>(tree);

        wots_addr.copy_subtree::<H>(&tree_addr);
        wots_addr.set_keypair_addr::<H>(leaf_idx);

        wots_pk_addr.copy_keypair::<H>(&wots_addr);

        let wots_pk = &mut wots_pk_buf[..H::WOTS_BYTES];
        wots_pk.fill(0);
        wots_pk_from_sig::<H>(
            wots_pk,
            &sig_bytes[sig_pos..sig_pos + H::WOTS_BYTES],
            root,
            pub_seed,
            &mut wots_addr,
        );
        sig_pos += H::WOTS_BYTES;

        let mut leaf = SecretArray::<u8, 32>::new();
        H::thash(
            &mut leaf[..n],
            wots_pk,
            H::WOTS_LEN,
            pub_seed,
            wots_pk_addr.as_bytes(),
        );

        let auth_path_len = H::TREE_H * n;
        compute_root::<H>(
            &mut root[..n],
            &leaf[..n],
            leaf_idx,
            0,
            &sig_bytes[sig_pos..sig_pos + auth_path_len],
            pub_seed,
            &mut tree_addr,
        );
        sig_pos += auth_path_len;

        leaf_idx = u32::try_from(tree & ((1u64 << H::TREE_H) - 1)).expect("value fits in u32");
        tree >>= H::TREE_H;
    }

    root == pub_root
}
