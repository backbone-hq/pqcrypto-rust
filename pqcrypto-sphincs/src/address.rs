use crate::hash::Hash;

pub(crate) const ADDR_TYPE_WOTS: u32 = 0;
pub(crate) const ADDR_TYPE_WOTSPK: u32 = 1;
pub(crate) const ADDR_TYPE_HASHTREE: u32 = 2;
pub(crate) const ADDR_TYPE_FORSTREE: u32 = 3;
pub(crate) const ADDR_TYPE_FORSPK: u32 = 4;
pub(crate) const ADDR_TYPE_WOTSPRF: u32 = 5;
pub(crate) const ADDR_TYPE_FORSPRF: u32 = 6;

#[derive(Clone, Copy)]
pub(crate) struct Adrs(pub [u8; 32]);

impl Adrs {
    pub(crate) fn new() -> Self {
        Self([0u8; 32])
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn copy_subtree<H: Hash>(&mut self, other: &Adrs) {
        let end = H::OFFSET_TREE + 8;
        self.0[..end].copy_from_slice(&other.0[..end]);
    }

    pub(crate) fn copy_keypair<H: Hash>(&mut self, other: &Adrs) {
        let end = H::OFFSET_TREE + 8;
        self.0[..end].copy_from_slice(&other.0[..end]);
        self.0[H::OFFSET_KP_ADDR2] = other.0[H::OFFSET_KP_ADDR2];
        self.0[H::OFFSET_KP_ADDR1] = other.0[H::OFFSET_KP_ADDR1];
    }

    pub(crate) fn set_layer_addr<H: Hash>(&mut self, layer: u32) {
        self.0[H::OFFSET_LAYER] = u8::try_from(layer).expect("layer fits in u8");
    }

    pub(crate) fn set_tree_addr<H: Hash>(&mut self, tree: u64) {
        let bytes = tree.to_be_bytes();
        self.0[H::OFFSET_TREE..H::OFFSET_TREE + 8].copy_from_slice(&bytes);
    }

    pub(crate) fn set_type(&mut self, offset: usize, typ: u32) {
        self.0[offset] = u8::try_from(typ).expect("type fits in u8");
    }

    pub(crate) fn set_keypair_addr<H: Hash>(&mut self, keypair: u32) {
        self.0[H::OFFSET_KP_ADDR2] =
            u8::try_from(keypair >> 8).expect("keypair high byte fits in u8");
        self.0[H::OFFSET_KP_ADDR1] =
            u8::try_from(keypair & 0xff).expect("keypair low byte fits in u8");
    }

    pub(crate) fn set_chain_addr<H: Hash>(&mut self, chain: u32) {
        self.0[H::OFFSET_CHAIN_ADDR] = u8::try_from(chain).expect("chain fits in u8");
    }

    pub(crate) fn set_hash_addr<H: Hash>(&mut self, hash: u32) {
        self.0[H::OFFSET_HASH_ADDR] = u8::try_from(hash).expect("hash fits in u8");
    }

    pub(crate) fn set_tree_height<H: Hash>(&mut self, height: u32) {
        self.0[H::OFFSET_TREE_HGT] = u8::try_from(height).expect("height fits in u8");
    }

    pub(crate) fn set_tree_index<H: Hash>(&mut self, index: u32) {
        let bytes = index.to_be_bytes();
        self.0[H::OFFSET_TREE_INDEX..H::OFFSET_TREE_INDEX + 4].copy_from_slice(&bytes);
    }
}
