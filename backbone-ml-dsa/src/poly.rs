use crate::field::Q;
use backbone_pqcrypto_internals::secret::SecretArray;

#[derive(Clone)]
pub(crate) struct Poly {
    pub coeffs: SecretArray<i32, 256>,
}

impl Default for Poly {
    fn default() -> Self {
        Self::new()
    }
}

impl Poly {
    pub(crate) fn new() -> Self {
        Self {
            coeffs: SecretArray::new(),
        }
    }

    pub(crate) fn add(&mut self, other: &Poly) {
        for i in 0..256 {
            self.coeffs[i] += other.coeffs[i];
        }
    }

    pub(crate) fn sub(&mut self, other: &Poly) {
        for i in 0..256 {
            self.coeffs[i] -= other.coeffs[i];
        }
    }

    /// Decompose(r, α): splits r into (a₁, a₀) where r ≡ a₁·α + a₀ (mod Q)
    /// with a₀ ∈ (-α/2, α/2].
    /// Matches C ref and FIPS 204 Algorithm 33.
    pub(crate) fn decompose(r: i32, alpha: i32) -> (i32, i32) {
        let mut a1 = r / alpha;
        let mut a0 = r - a1 * alpha;
        if a0 >= alpha / 2 {
            a0 -= alpha;
            a1 += 1;
        }
        let max_a1 = (Q - 1) / alpha;
        if a1 >= max_a1 {
            return (0, r - Q);
        }
        (a1, a0)
    }

    /// Compute corrected high bits from value and hint.
    /// Matches C reference: decompose, then adjust a₁ by ±1 with wrap at [0, max].
    pub(crate) fn use_hint(r: i32, hint: i32, gamma2: i32) -> i32 {
        let (a1, a0) = Self::decompose(r, gamma2 * 2);
        if hint == 0 {
            return a1;
        }
        let max_bits = (Q - 1) / (gamma2 * 2) - 1;
        if a0 > 0 {
            if a1 == max_bits {
                0
            } else {
                a1 + 1
            }
        } else if a1 == 0 {
            max_bits
        } else {
            a1 - 1
        }
    }

    /// Power2Round: splits r into (r₁, r₀) where r = r₁·2^d + r₀, r₀ ∈ (-2^{d-1}, 2^{d-1}]
    /// Assumes r is a standard representative in [0, Q-1].
    /// Matches C reference: a1 = (a + (1<<(D-1)) - 1) >> D; a0 = a - (a1 << D)
    pub(crate) fn power2round(r: i32, d: i32) -> (i32, i32) {
        let r1 = (r + (1 << (d - 1)) - 1) >> d;
        let r0 = r - (r1 << d);
        (r1, r0)
    }

    /// Infinity norm: max |coeff| (handles both [0,Q) and centered representation)
    /// Computed without data-dependent branches (constant-time).
    pub(crate) fn infinity_norm(&self) -> i32 {
        let mut max_val = 0i32;
        for &c in self.coeffs.iter() {
            // CT absolute value: (x ^ (x >> 31)) - (x >> 31) = |x|
            let abs_c = (c ^ (c >> 31)).wrapping_sub(c >> 31);
            // CT centered reduction: if abs_c > Q/2 then use Q - abs_c
            let mask = (Q.wrapping_sub(abs_c << 1)) >> 31; // -1 when abs_c > Q/2
            let centered = (mask & (Q - abs_c)) | (!mask & abs_c);
            // CT max: update max_val = max(max_val, centered)
            let update_mask = (max_val.wrapping_sub(centered)) >> 31;
            max_val ^= update_mask & (max_val ^ centered);
        }
        max_val
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_add_sub() {
        let mut p1 = Poly::new();
        p1.coeffs[0] = 1000;
        let mut p2 = Poly::new();
        p2.coeffs[0] = 500;

        let mut p3 = p1.clone();
        p3.add(&p2);
        assert_eq!(p3.coeffs[0], 1500);

        p3.sub(&p2);
        assert_eq!(p3.coeffs[0], 1000);
    }
}
