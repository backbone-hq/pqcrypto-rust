// ── Typed encaps / decaps wrappers ──────────────────────────────────────
// (Included after core_fft*.rs so that PublicKey, SecretKey, encaps(),
//  decaps(), and Encapsulation are in scope.)

impl PublicKey {
    /// Encapsulate a shared secret under this public key (uses system
    /// randomness for the error vector).
    pub fn encaps(&self) -> Result<Encapsulation, crate::error::Error> {
        encaps(&self.pk)
    }

    /// Encapsulate a shared secret under this public key using a specific
    /// 32-byte seed (deterministic).
    #[must_use]
    pub fn encaps_from_seed(&self, seed32: [u8; 32]) -> Encapsulation {
        encaps_from_seed(&self.pk, seed32)
    }
}

impl SecretKey {
    /// Decapsulate a shared secret from a ciphertext using this secret key.
    pub fn decaps(&self, ct: &[u8]) -> Result<[u8; CRYPTO_BYTES], crate::error::Error> {
        decaps(&self.sk, ct)
    }
}
