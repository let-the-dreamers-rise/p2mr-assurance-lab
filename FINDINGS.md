# Findings — independent differential testing of the BIP 360 reference implementation

**Method.** An independent from-scratch implementation of P2MR construction and
script-path validation (`p2mr.py`) was tested against the official Python
reference implementation vendored at `bitcoin/bips` commit `ed4ffcb6`
(`differential/upstream/p2mr_ref.py`, BSD-3-Clause). Both are pinned by SHA-256.

**Baseline agreement (the control).** The two implementations agree, byte for
byte, on:

- all 9 official construction vectors and all 7 official PQC construction vectors, and
- 2000 seeded randomized script trees (seed 360) across merkle root, control
  blocks, and address.

That agreement is the point: it establishes the independent implementation is
correct on the shared domain, so the divergences below are signal, not the noise
of a broken reimplementation.

Reproduce everything with: `python differential/run_differential.py`

---

Divergences are graded honestly. Two are conformance/robustness gaps in the
reference; two are cases where this lab is deliberately *stricter* than the
reference and the “correct” behavior is a legitimate open question for the BIP
authors, not a decided bug. Nothing here is a consensus break, and none of it
means Bitcoin is unsafe.

## F2 — reference emits control blocks the spec says must be rejected *(real gap, low severity)*

BIP 360, Script Validation: the control block “must have length 1 + 32 * m, for a
value of m that is an integer between 0 and 128, inclusive.” The reference's
`compute_control_block` / `compute_merkle_root` apply no depth bound, so for a
tree deeper than 128 the reference happily produces a control block with m = 129
(4129 bytes) — an output that consensus validation must reject as unspendable.
This lab refuses such a tree at construction time. Severity is low (129-deep
trees are pathological in practice), but a reference implementation that can mint
an unspendable output is a legitimate conformance gap worth a guard and a test.

## F4 — structural validation via `assert`, stripped under `python -O` *(real robustness gap, low–moderate severity)*

The reference enforces the binary-tree invariant with `assert len(tree) == 2`.
Python run with `-O` strips assertions, so under optimized execution a malformed
ternary branch does not raise — it silently produces a wrong merkle root rather
than an error. Using `assert` for input validation is a well-known anti-pattern
precisely because of this. This lab raises a typed domain error instead. Fix is a
one-line change to an explicit raise; the value is in flagging it before wallets
copy the pattern.

## F1 — empty-script leaves: reference refuses, lab constructs *(divergence, open question)*

The reference's `tapleaf_hash` raises on an empty script; this lab will hash and
commit an empty-script leaf. Which is correct is genuinely open: an empty script
is representable at the tapleaf layer, but a maintainer may reasonably choose to
reject it defensively. Flagged as a question for the BIP authors, **not** as a
reference bug.

## F3 — odd leaf versions: reference masks silently, lab refuses *(divergence, open question)*

The spec interprets the leaf version as `v = c[0] & 0xfe`, and the reference
applies that mask at construction, silently coercing e.g. `0xc1` to `0xc0`. This
lab rejects odd leaf versions rather than silently normalizing them. The
reference's behavior is arguably spec-faithful; the lab's is arguably safer
(surprising input should not be silently rewritten). A defensible
difference in strictness, flagged for discussion — **not** a reference bug.

---

## Disclosure posture

F2 and F4 are the substantive items. Per this lab's coordinated-disclosure
policy, they will be reported to the BIP 360 authors with a pinned reproducer and
a suggested regression test before any public write-up, and re-tested after any
fix. F1 and F3 are framed to the authors as questions, not defects. This document
records the state of the analysis at the pinned commit; it will be versioned as
the draft evolves.
