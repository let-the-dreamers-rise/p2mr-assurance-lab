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

`vectors.json` holds 231 cases, every expected value computed by this lab's
`p2mr.py` (which agrees byte for byte with the pinned BIP 360 reference):

| Group | Cases | What it checks |
|---|---|---|
| official | 8 | Every official BIP 360 construction vector that takes only a script tree, checked against its published expected values when the pack is generated |
| boundary | 7 | Depth exactly 128 (accept), depth 129 (reject, the gap fixed in bitcoin/bips#2273), odd leaf version 0xc1 (reject, never coerce), a three-child branch (reject), duplicate leaves, non-default even leaf versions, an empty script |
| random | 200 | Seeded random trees (seed 360), depth 0 to 7, mixed leaf versions |
| spend | 16 | Script-path spend validation, for node and validator code: honest spends (including m = 0, m = 128 and leaf version 0x00) must pass; m = 129, an appended zero element, wrong lengths, a parity bit of 0, a wrong leaf version, reversed path order, an uncommitted script and a foreign witness program must all be rejected |

For each tree case it checks the scriptPubKey, the mainnet bech32m address,
and the control block of every leaf in depth-first order.

## Run it against your implementation

Python 3.10+, no packages, no network.

```sh
python conformance/check.py --adapter "<command that runs your adapter>"
```

The adapter contract:

- **stdin**: a JSON array of `{"id": ..., "script_tree": ...}` or, for spend
  cases, `{"id": ..., "spend": {"program", "script", "control"}}` (hex). The tree uses BIP
  360's own vector format: a leaf is `{"script": "<hex>", "leafVersion": 192}`, a
  branch is a two-element array `[left, right]`.
- **stdout**: a JSON array with one object per case, either
  `{"id", "script_pubkey", "address", "control_blocks"}` (hex strings; control
  blocks in depth-first leaf order), `{"id", "valid": true}` for an accepted
  spend, or `{"id", "error": "<message>"}` when your library rejects the input.
  A library that only builds outputs can skip spends with `--group official
  --group boundary --group random`; one that only validates can run `--group spend`.

Exit status is 0 only if every case conforms. `--json report.json` writes a
machine-readable report; `--group boundary` runs one group.

Ready adapters:

| Adapter | Run |
|---|---|
| This lab's `p2mr.py` (self-test) | `python conformance/check.py --adapter "python conformance/adapters/reference.py"` |
| bitcoinjs-lib (PR #2312 branch, built) | `BJS=/path/to/bitcoinjs-lib python conformance/check.py --adapter "node conformance/adapters/bitcoinjs.mjs"`. Result: 225/231 at `e079eb4` on 2026-10-05; failures explained in `implementations/bitcoinjs-lib/README.md` |

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
