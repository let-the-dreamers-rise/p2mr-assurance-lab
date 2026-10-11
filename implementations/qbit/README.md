# Qbit P2MR v1: independent vector check

Target: [Qbit-Org/qbit](https://github.com/Qbit-Org/qbit) v1.0.0 (`70fea84`). Spec: `doc/consensus/p2mr-v1.md`.

Qbit's P2MR v1 is not byte-identical to BIP 360 on purpose: it uses its own `P2MRLeaf` / `P2MRBranch` tagged-hash domains. `check_vectors.py` is a from-scratch checker written from the spec, with no Qbit code. It recomputes Qbit's published vectors.

## Result (2026-10-02)

- `p2mr_vectors.json`: all 4 valid vectors agree (leaf hash, root, scriptPubKey, control-block verification). All 7 invalid vectors fail with the expected error class.
- `p2mr_cross_profile_vectors.json`: both cross-profile vectors agree, for the qbit `P2MRLeaf` root and the BIP 360 `TapLeaf` root alike.
- A read of the witness v2 path in `src/script/interpreter.cpp` matches the spec. It enforces 0 <= m <= 128, bit 0 of the control byte, the 0xfe leaf-version mask and annex handling, and lets unknown leaf versions succeed. Qbit's boundary vectors already cover m = 128 and m = 129.

No divergences found.

## Reproduce

```sh
QBIT_DATA=/path/to/qbit/src/test/data python3 implementations/qbit/check_vectors.py
```
