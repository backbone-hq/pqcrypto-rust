# backbone-hqc

HQC (FIPS 207) — Hamming Quasi-Cyclic Key Encapsulation Mechanism.

A code-based KEM whose security reduces to the hardness of decoding
quasi-cyclic codes — specifically the syndrome decoding problem for
Hamming metric codes. Uses repeated codes, Reed-Muller codes, and
Reed-Solomon codes for error correction.

Three variants:

| Variant | Security level | PK bytes | SK bytes | CT bytes |
| --- | --- | --- | --- | --- |
| HQC-128 | 1 (128-bit) | 2241 | 2321 | 4433 |
| HQC-192 | 3 (192-bit) | 4514 | 4602 | 8978 |
| HQC-256 | 5 (256-bit) | 7237 | 7333 | 14421 |

Implementation uses GF(2) polynomial multiplication via Karatsuba
for the core quasi-cyclic operations.

## Validation

Cross-validated byte-for-byte against the official C reference
implementation (pqc-hqc, FIPS 207). The bundled KAT vectors are the official
`kats/ref` values (all three variants regenerated in full from a fresh
reference build — 100 entries per variant), and live interop against a fresh
pqc-hqc v5.0.0 build passes in both directions (identical keys/ciphertexts
from the same seed; matching shared secrets). NIST ACVP vectors not yet
available for FIPS 207.

## Other Implementations

- **Official Reference (C)**: [pqc-hqc/hqc](https://gitlab.com/pqc-hqc/hqc)
- **liboqs (C)**: [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)
- **PQClean (C)**: [PQClean/PQClean](https://github.com/PQClean/PQClean)
