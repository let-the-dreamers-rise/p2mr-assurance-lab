# P2MR conformance kit

One file of test cases and one command that tells any BIP 360 (P2MR)
implementation, in any language, whether it builds the same outputs as the
specification. It is the portable form of this lab's suite: you write a small
adapter for your library, and `check.py` does the rest.

> BIP 360 is a Draft and is not activated on mainnet. Passing this pack is
> conformance evidence, not a security review or a claim of mainnet readiness.
> P2MR can mitigate long-exposure (revealed-key) risk only under fresh-key
> discipline; nothing here makes Bitcoin quantum-safe today.

## What is in the pack

`vectors.json` holds 215 cases, every expected value computed by this lab's
`p2mr.py` (which agrees byte for byte with the pinned BIP 360 reference):

| Group | Cases | What it checks |
|---|---|---|
| official | 8 | Every official BIP 360 construction vector that takes only a script tree, checked against its published expected values when the pack is generated |
| boundary | 7 | Depth exactly 128 (accept), depth 129 (reject, the gap fixed in bitcoin/bips#2273), odd leaf version 0xc1 (reject, never coerce), a three-child branch (reject), duplicate leaves, non-default even leaf versions, an empty script |
| random | 200 | Seeded random trees (seed 360), depth 0 to 7, mixed leaf versions |

For each accepted tree it checks the scriptPubKey, the mainnet bech32m address,
and the control block of every leaf in depth-first order.

## Run it against your implementation

Python 3.10+, no packages, no network.

```sh
python conformance/check.py --adapter "<command that runs your adapter>"
```

The adapter contract:

- **stdin**: a JSON array of `{"id": ..., "script_tree": ...}`. The tree uses BIP
  360's own vector format: a leaf is `{"script": "<hex>", "leafVersion": 192}`, a
  branch is a two-element array `[left, right]`.
- **stdout**: a JSON array with one object per case, either
  `{"id", "script_pubkey", "address", "control_blocks"}` (hex strings; control
  blocks in depth-first leaf order) or `{"id", "error": "<message>"}` when your
  library rejects the tree.

Exit status is 0 only if every case conforms. `--json report.json` writes a
machine-readable report; `--group boundary` runs one group.

Ready adapters:

| Adapter | Run |
|---|---|
| This lab's `p2mr.py` (self-test) | `python conformance/check.py --adapter "python conformance/adapters/reference.py"` |
| bitcoinjs-lib (PR #2312 branch, built) | `BJS=/path/to/bitcoinjs-lib python conformance/check.py --adapter "node conformance/adapters/bitcoinjs.mjs"` (built from the harness behind the 2026-10-02 results in `implementations/bitcoinjs-lib/`; not yet run against this pack) |

Writing one for your library is usually 30 lines: parse the tree, call your
P2MR constructor, print the three values.

## Add it to your CI

```yaml
- uses: actions/checkout@v4
  with: { repository: let-the-dreamers-rise/p2mr-assurance-lab, path: p2mr-kit }
- run: python p2mr-kit/conformance/check.py --adapter "<your adapter command>"
```

## Regenerate

`python conformance/gen_vectors.py` rebuilds `vectors.json` deterministically and
prints its SHA-256. CI regenerates it and fails if the committed file differs.

Questions or a library you want covered: open an issue on this repository.
