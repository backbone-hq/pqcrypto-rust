impl PublicKey {
    /// randomness for the error vector).
    pub fn encaps(&self) -> Result<Encapsulation, crate::error::Error> {
        encaps(&self.pk)
    }

    /// 32-byte seed (deterministic).
    #[must_use]
    pub fn encaps_from_seed(&self, seed32: [u8; 32]) -> Encapsulation {
        encaps_from_seed(&self.pk, seed32)
    }
}

impl SecretKey {
    pub fn decaps(&self, ct: &[u8]) -> Result<[u8; CRYPTO_BYTES], crate::error::Error> {
        decaps(&self.sk, ct)
    }
}
