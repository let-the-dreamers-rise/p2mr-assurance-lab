# bitcoinjs-lib P2MR (PR #2312): differential results

Target: [bitcoinjs/bitcoinjs-lib#2312](https://github.com/bitcoinjs/bitcoinjs-lib/pull/2312) at commit `e079eb4`.
Oracle: this lab's `p2mr.py`, which agrees byte for byte with the BIP 360 reference (see `../../FINDINGS.md`).

## Result (run 2026-10-02)

**2006 of 2007 cases agree byte for byte.** That covers 7 official construction vectors plus 2,000 seeded random trees (seed 360). Every scriptPubKey and address matches, and every reference control block validates against the bitcoinjs output.

| ID | What | Severity |
|---|---|---|
| B1 | Duplicate leaves: for `[A, [B, A]]`, spending A returns the depth-2 control block (65 bytes) instead of the depth-1 one (33 bytes). `findScriptPath` returns the first DFS hit, not the shortest. | Low: valid, but 32 bytes heavier, and it diverges from the reference |
| B2 | No depth bound when building a witness: a 129-deep tree yields a witness with m = 129, which bitcoinjs's own validator then rejects (`The script path is too long. Got 129, expected max 128.`). This is the same class as F2, fixed in the reference by bitcoin/bips#2273. | Low: pathological trees only |
| - | Odd leaf version `0xc1`: already rejected by the taptree type check. | No issue |

## Conformance kit run (2026-10-05, same commit `e079eb4`)

`conformance/check.py` with `conformance/adapters/bitcoinjs.mjs`: **225 of 231
cases pass.** The six failures are B1 (three duplicate-leaf cases), B2 (depth 129
accepted), and one new class:

| ID | What | Severity |
|---|---|---|
| B3 | Leaf version `0x00` is hashed as `0xc0`. `tapleafHash` in `ts_src/payments/bip341.ts` uses `leaf.version \|\| LEAF_VERSION_TAPSCRIPT`, and `0` is falsy. Building an output for a `0x00` leaf commits to the wrong leaf hash, and a valid spend of a `0x00` leaf is rejected (`Hash mismatch for p2mr witness`). The same line is on bitcoinjs-lib `master` and is shared with P2TR: a P2TR output for a `0x00` leaf is byte-identical to the `0xc0` one. | Low: only `0xc0` is in use today, but other even versions are valid upgrade hooks and this silently commits to a different script |

Changing `||` to `??` fixes B3: with that one-character change the kit's two
leaf-version failures pass, the P2TR outputs differ as they should, and
bitcoinjs-lib's own suite still passes (2695 tests).

## Reproduce

```sh
git clone https://github.com/bitcoinjs/bitcoinjs-lib && cd bitcoinjs-lib
git fetch origin pull/2312/head:p2mr && git checkout p2mr && npm ci && npm run build
cd /path/to/p2mr-assurance-lab/implementations/bitcoinjs-lib
python3 gen_cases.py                 # writes cases.json (7 vectors + 2000 random trees)
BJS=/path/to/bitcoinjs-lib node run.mjs    # differential
BJS=/path/to/bitcoinjs-lib node edge.mjs   # depth-129 and odd-version probes
cd /path/to/p2mr-assurance-lab
BJS=/path/to/bitcoinjs-lib python3 conformance/check.py --adapter "node conformance/adapters/bitcoinjs.mjs"
```
