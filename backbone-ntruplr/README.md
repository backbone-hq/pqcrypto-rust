# backbone-ntruplr

NTRU LPRime — lattice-based Key Encapsulation Mechanism, NIST Round 2
candidate.

An NTRU-based KEM using a key format that applies the "Prime" principle
(simplified rings, no "decryption failures") from the NTRU Prime family.
Uses ring arithmetic in `Z_q[x]/(x^p - x - 1)`. Designed by Bernstein,
Chuengsatiansup, Lange, and van Vredendaal.

6 variants:

| Variant | p | w | PK bytes | SK bytes | CT bytes |
| --- | --- | --- | --- | --- | --- |
| ntruplr653 | 653 | 252 | 897 | 1125 | 1025 |
| ntruplr761 | 761 | 250 | 1039 | 1294 | 1167 |
| ntruplr857 | 857 | 281 | 1184 | 1463 | 1312 |
| ntruplr953 | 953 | 345 | 1349 | 1652 | 1477 |
| ntruplr1013 | 1013 | 392 | 1455 | 1773 | 1583 |
| ntruplr1277 | 1277 | 429 | 1847 | 2231 | 1975 |

Key generation expands the 48-byte seed via the NIST AES-256 CTR_DRBG
seedexpander (SP 800-90A), matching the official reference KAT harness.

## Validation

KATs are the official NIST submission package vectors
(ntruprime-20201007, ntruprime.cr.yp.to). Keygen (DRBG-expanded 48-byte
seed), encaps (r from the package's intermediate-value files), and decaps
are validated byte-for-byte against them for all 6 variants, 100 entries
each. NIST ACVP vectors not available (NTRU Prime not on the FIPS track).

## Other Implementations

- **Official Reference (C)**: [ntruprime.cr.yp.to](https://ntruprime.cr.yp.to/)
- **liboqs (C)**: [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)
- **PQClean (C)**: [PQClean/PQClean](https://github.com/PQClean/PQClean)
