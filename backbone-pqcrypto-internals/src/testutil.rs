//! Deterministic test fixtures shared across workspace test suites.

/// Deterministic xorshift64 PRNG for generating reproducible garbage data in
/// robustness tests. Not for cryptographic use.
#[derive(Clone, Copy, Debug)]
pub struct XorShift(u64);

impl XorShift {
    /// Create a generator with a fixed nonzero seed.
    #[must_use]
    pub fn new() -> Self {
        Self(0x9E3779B97F4A7C15)
    }

    /// Create a generator with an explicit seed, so different tests can
    /// draw independent input sequences.
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        Self(seed)
    }

    /// Next pseudorandom 64-bit value.
    #[must_use]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Fill `buf` with pseudorandom bytes.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = (self.next_u64() & 0xFF) as u8;
        }
    }
}

impl Default for XorShift {
    fn default() -> Self {
        Self::new()
    }
}
