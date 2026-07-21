# pqcrypto-hqc

HQC (FIPS 209) — Hamming Quasi-Cyclic Key Encapsulation Mechanism.

A code-based KEM whose security reduces to the hardness of decoding
quasi-cyclic codes — specifically the syndrome decoding problem for
Hamming metric codes. Uses repeated codes, Reed-Solomon codes, and
a BCH decoder for error correction.

Three variants:

| Variant | Security level | PK bytes | SK bytes | CT bytes |
|---|---|---|---|---|
| HQC-128 | 1 (128-bit) | 2249 | 2305 | 4481 |
| HQC-192 | 3 (192-bit) | 4482 | 4546 | 8961 |
| HQC-256 | 5 (256-bit) | 8961 | 9025 | 17921 |

Implementation uses GF(2) polynomial multiplication via Karatsuba
for the core quasi-cyclic operations.

## Other Implementations

- **Official Reference (C)**: [pqc-hqc/hqc](https://gitlab.com/pqc-hqc/hqc)
- **liboqs (C)**: [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)
- **PQClean (C)**: [PQClean/PQClean](https://github.com/PQClean/PQClean)
