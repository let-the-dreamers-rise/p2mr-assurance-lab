# Post-quantum parameter sizes used by `pqc_bench.py`

All values are the fixed, standardized public-key and signature byte sizes from
the final NIST standards. They are constants, not measurements.

## FIPS 204 — ML-DSA (module-lattice, formerly Dilithium)

| Parameter set | NIST level | Public key (B) | Signature (B) |
| --- | --- | --- | --- |
| ML-DSA-44 | 2 | 1312 | 2420 |
| ML-DSA-65 | 3 | 1952 | 3309 |
| ML-DSA-87 | 5 | 2592 | 4627 |

## FIPS 205 — SLH-DSA (stateless hash-based, formerly SPHINCS+)

| Parameter set | NIST level | Public key (B) | Signature (B) |
| --- | --- | --- | --- |
| SLH-DSA-128s | 1 | 32 | 7856 |
| SLH-DSA-128f | 1 | 32 | 17088 |
| SLH-DSA-192s | 3 | 48 | 16224 |
| SLH-DSA-256s | 5 | 64 | 29792 |

## Baseline

| Scheme | Public key (B) | Signature (B) |
| --- | --- | --- |
| BIP 340 Schnorr / secp256k1 | 32 | 64 |

## Sources

- NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard* (2024).
- NIST FIPS 205, *Stateless Hash-Based Digital Signature Standard* (2024).
- The Open Quantum Safe project's algorithm tables reproduce the same sizes and
  are used to cross-check the constants above.

The funded benchmark pins an exact liboqs (or equivalent) build and adds
measured verification cost, malformed-input behavior, and reproducibility
metadata to every number; this starter table establishes the size/fee/capacity
results that published constants alone already determine.
