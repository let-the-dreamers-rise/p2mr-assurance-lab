# P2MR Assurance Lab

Independent conformance testing for BIP 360 (Pay-to-Merkle-Root) **and the first
open measurement of what post-quantum signatures would cost inside a Bitcoin
transaction** — the question BIP 360's own design leaves open.

Three things live here, all reproducible in minutes with zero dependencies:

1. **A post-quantum cost model** (`pqc/`) — what ML-DSA (FIPS 204) and SLH-DSA
   (FIPS 205) signatures cost as real Bitcoin witness data. Headline result: a
   post-quantum P2MR input costs **17x to 131x** a Schnorr key-path spend, and
   block input capacity falls from ~17,391 to as few as **133** inputs.
2. **An independent differential audit** (`differential/`) — a from-scratch
   implementation cross-checked against the official reference on 13 official
   vectors and 2000 random trees, which surfaced **four graded divergences —
   two of them real conformance/robustness gaps in the reference**, two flagged
   to the BIP authors as open questions rather than defects (see `FINDINGS.md`).
3. **A pinned conformance suite** — official vectors, boundary tests, and an
   adversarial mutation corpus in which every case cites the specification text
   that defines its expected outcome.

> BIP 360 (P2MR) is a Draft and is not activated on Bitcoin mainnet. P2MR can
> mitigate long-exposure (revealed-key) risk only under fresh-key discipline; it
> does not by itself defend the reveal-to-confirmation window, and nothing in
> this work makes Bitcoin quantum-safe today.

## Test your own P2MR implementation

`conformance/` is a portable kit: 215 cases (official vectors, spec boundaries,
seeded random trees) and one command that checks any library, in any language,
through a small adapter. See [`conformance/README.md`](conformance/README.md).

```
python conformance/check.py --adapter "<command that runs your adapter>"
```

## Verify (ten minutes, zero dependencies)

Python 3.10+. No packages, no network access, no configuration.

```
git clone https://github.com/let-the-dreamers-rise/p2mr-assurance-lab
cd p2mr-assurance-lab
python verify_vectors.py                    # official vectors + boundary tests
python run_mutations.py                     # adversarial mutation corpus
python differential/run_differential.py     # vs the official reference impl
python pqc/pqc_bench.py                      # post-quantum cost measurement
```

Expected output (tail of each run):

```
9/9 official BIP 360 construction vectors PASS (byte-for-byte)
7/7 official BIP 360 PQC construction vectors PASS (byte-for-byte)
8/8 local boundary tests PASS
pinned: bitcoin/bips @ ed4ffcb6a48d4dc4fdfc11cdba783c233db8c66e
fixture: p2mr_construction.json  sha256: cd02da0b3c5bcbea98ed4d3141ebaf71344ee5acc8eb543841b7d2ed853251c7
fixture: p2mr_pqc_construction.json  sha256: 3bd10ece56cb52c2616d5d7ff341afb5b039bc75a8b55caf680e74805a3cf454
```

```
27/27 adversarial mutation cases PASS
every case cites the specification text that defines its expected outcome
```

```
13/13 official construction vectors: full agreement with the reference implementation
2000/2000 randomized trees: full agreement (seed 360)
4/4 documented divergences reproduced -- details in FINDINGS.md
pinned: bitcoin/bips @ ed4ffcb6a48d4dc4fdfc11cdba783c233db8c66e
```

Every runner exits non-zero on any failure, and each refuses to run if a local
fixture's SHA-256 does not match the pin in `vectors/MANIFEST.json` -- results
against an unpinned or altered fixture are meaningless and are not produced.

These numbers are the current output, not an aspiration. If a clean clone prints
anything else, that is a defect in this repository and should be reported.

## What is checked

**Official vectors (9 construction + 7 PQC construction).** Every field each
fixture provides is compared
byte-for-byte: leaf hashes (depth-first order), merkle root, scriptPubKey,
BIP 350 bech32m address, and script-path control blocks. The two misuse vectors
must be *refused* with the exact specified error -- and for the internal-pubkey
misuse case, the verifier independently recomputes the documented P2TR-style
tweak (secp256k1, implemented from scratch) to confirm the bytes a faulty
implementation would produce. For every construction vector, each leaf's
(script, control block) pair is additionally walked back through the BIP 360
script-path validation rules to the committed witness program.

**Boundary tests (8).** Edges the official vectors do not exercise:
CompactSize encoding boundaries (252/253, 16/32-bit), odd leaf-version
rejection, the merkle-path depth limit (m = 128 accepted, m = 129 refused),
TapBranch pair-sorting commutativity, bech32m round-trip plus checksum
corruption, strict 32-byte witness-program length, SegWit version
discrimination (a v1 output must not parse as P2MR), and full control-block
reconstruction for a fresh multi-leaf tree.

**Adversarial mutations (27).** Each case starts from an official vector,
applies one machine-defined mutation -- merkle-path byte flips, control-block
truncation/extension, parity-bit clearing (the specification requires the
control byte's low bit to be 1), leaf-version mismatches, script tampering,
path reordering, scriptPubKey shape violations, and address-encoding attacks
including the legacy-bech32-constant case -- and asserts the outcome the
specification requires, with the citation recorded in
`mutations/corpus.json`.

## Pins

| Item | Value |
| --- | --- |
| Upstream repository | `bitcoin/bips` |
| Commit | `ed4ffcb6a48d4dc4fdfc11cdba783c233db8c66e` |
| Fixture path | `bip-0360/ref-impl/common/tests/data/p2mr_construction.json` |
| Fixture SHA-256 | `cd02da0b3c5bcbea98ed4d3141ebaf71344ee5acc8eb543841b7d2ed853251c7` |

The fixture in `vectors/` is a byte-identical copy of the upstream file at the
pinned commit. BIP 360 is an evolving Draft; a test claim without its exact
revision is weak evidence, so nothing here runs against moving `master`.

## Layout

```
CHARTER.md           scope, hard exclusions, evidence rules, acceptance criteria
LEDGER.md            funds ledger (nothing received, nothing spent)
p2mr.py              construction + validation primitives (zero dependencies)
verify_vectors.py    official vectors + boundary tests (entry point)
run_mutations.py     adversarial mutation corpus runner
pinning.py           sha256 pin enforcement shared by every runner
differential/        run_differential.py + vendored pinned reference impl
implementations/     differential runs against other P2MR implementations (bitcoinjs-lib)
pqc/                 pqc_bench.py + PARAMS.md (post-quantum cost model)
vectors/             pinned official fixtures + MANIFEST.json
mutations/           corpus.json -- one citation per case
FINDINGS.md          graded results of the differential audit
docs/                grant proposal (PDF)
```

## Status and non-claims

This repository is the public baseline (M0) of a Phase 1 proposal to the Galaxy
Bitcoin Quantum Readiness Initiative: `docs/galaxy-proposal.pdf`. The proposed
program expands this baseline into a 250+ case corpus, a cross-implementation
differential test matrix, and a published conformance report.

The scope, the hard exclusions, the evidence rules, and the written test for
calling a milestone complete are in [`CHARTER.md`](CHARTER.md). The funds
position -- currently nothing received and nothing spent -- is in
[`LEDGER.md`](LEDGER.md).

What this repository does **not** claim:

- No review, endorsement, or approval by the BIP 360 authors, Bitcoin Core, or
  any implementation maintainer.
- No security audit. The word "audit" is reserved for qualified external
  auditors under contract, which this is not.
- No fitness for constructing mainnet outputs. P2MR is a Draft; depth-zero
  trees in particular are anyone-can-spend under current rules.
- No handling of secret material, ever: no seeds, no private keys, no signing,
  no broadcasting, no telemetry.

Discrepancies found against any real implementation will follow coordinated
disclosure: pinned reproduction to maintainers first, publication of facts
only, full corpus retest after any fix.

## License and contact

MIT. Ashwin Goyal -- ashwingoyal2006@gmail.com --
[github.com/let-the-dreamers-rise](https://github.com/let-the-dreamers-rise)
