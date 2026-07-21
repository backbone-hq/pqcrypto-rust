# backbone-ntruplr

NTRU LPRime — lattice-based Key Encapsulation Mechanism, NIST Round 4 candidate.

An NTRU-based KEM using a key format that applies the "Prime" principle
(simplified rings, no "decryption failures") from the NTRU Prime family.
Uses ring arithmetic in `Z_q[x]/(x^p - x - 1)` with `q = 4591`.

Two variants:

| Variant | p | PK bytes | SK bytes | CT bytes |
|---|---|---|---|---|
| ntruplr653 | 653 | 897 | 1125 | 1025 |
| ntruplr761 | 761 | 1039 | 1294 | 1167 |

Supports both SHAKE-256 key derivation and an `#[cfg(feature = "drbg")]`
AES-CTR DRBG path for KAT reproduction.

## Other Implementations

- **Official Reference (C)**: [ntruprime.cr.yp.to](https://ntruprime.cr.yp.to/)
- **liboqs (C)**: [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)
- **PQClean (C)**: [PQClean/PQClean](https://github.com/PQClean/PQClean)
