# backbone-sntrup

Streamlined NTRU Prime — lattice-based Key Encapsulation Mechanism,
NIST Round 2 candidate.

A KEM using the "Prime" design principle: ring arithmetic over
`Z_q[x]/(x^p - x - 1)` with carefully chosen parameters to eliminate
decryption failures entirely. Designed by Bernstein, Chuengsatiansup,
Lange, and van Vredendaal.

6 variants:

| Variant | p | q | w | PK bytes | SK bytes | CT bytes |
| --- | --- | --- | --- | --- | --- | --- |
| sntrup653 | 653 | 4621 | 288 | 994 | 1518 | 897 |
| sntrup761 | 761 | 4591 | 286 | 1158 | 1763 | 1039 |
| sntrup857 | 857 | 5167 | 322 | 1322 | 1999 | 1184 |
| sntrup953 | 953 | 6343 | 396 | 1505 | 2254 | 1349 |
| sntrup1013 | 1013 | 7177 | 448 | 1623 | 2417 | 1455 |
| sntrup1277 | 1277 | 7879 | 492 | 2067 | 3059 | 1847 |

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
- **streamlined-ntru-prime (Rust)**: [mberry/Streamlined-NTRU-Prime](https://github.com/mberry/Streamlined-NTRU-Prime) — crate: [`streamlined-ntru-prime`](https://crates.io/crates/streamlined-ntru-prime)
