# Scope and acceptance charter

This is the M0 charter for the P2MR Assurance Lab program proposed to the Galaxy
Bitcoin Quantum Readiness Initiative (`docs/galaxy-proposal.pdf`). It states what
the work is, what it is not, and the exact conditions under which a milestone may
be called complete. It exists so that "done" is decided by a written test rather
than by the author's judgement.

## 1. What this program is

Independent engineering and security-assurance tooling for **BIP 360
(Pay-to-Merkle-Root)**, a Draft Bitcoin proposal that is **not activated on
mainnet**. The work makes an existing proposal more testable for wallet teams,
custodians, and reviewers. It does not propose a consensus change, and it does
not ship a wallet.

## 2. Standing boundary (repeated in every deliverable)

P2MR can mitigate long-exposure (revealed-key) risk **only under fresh-key
discipline**. It does not by itself defend the reveal-to-confirmation window, and
nothing produced here makes Bitcoin quantum-safe today. No deliverable, README,
commit message, or public statement may drop this boundary.

## 3. Hard exclusions

These are not "unlikely", they are forbidden for the life of the program:

- No handling, acceptance, or transmission of secret material: no seeds, no
  xprv/WIF, no wallet databases, no signing-device backups.
- No transaction signing and no broadcasting, on any network.
- No telemetry, analytics, or phone-home of any kind.
- No token, bridge, trading product, mining scheme, or marketing campaign.
- No claim of review, endorsement, or approval by the BIP 360 authors, Bitcoin
  Core, or any implementation maintainer.
- The word **audit** is reserved for a qualified external auditor under a
  separately scoped contract, and is not used for this lab's own testing.
- No claim of mainnet readiness or fitness for constructing mainnet outputs.

## 4. Evidence rules

1. **Nothing runs against moving `master`.** Every result names the exact
   upstream commit and fixture SHA-256 it was produced against.
2. **A fixture mismatch halts the run.** Runners refuse to execute if a local
   fixture's hash does not match `vectors/MANIFEST.json`. Results against an
   unpinned or altered fixture are not produced at all.
3. **Every failing case ships a minimized reproducer** plus the expected
   behaviour and the specification text that defines it.
4. **A blocked milestone is reported as blocked**, never relabelled complete.
5. **Divergences are graded.** A difference between this lab and a reference
   implementation is classified as a real gap or as an open question for the BIP
   authors, and the two are never presented as if they were the same thing.

## 5. Acceptance criteria

### M0 — public baseline (this tag)

Accepted when an independent reviewer, on a machine that has never seen this
project, can do all of the following:

- [x] Clone the repository at a **public tag** and run four commands with no
      packages, no network, and no configuration.
- [x] Observe output that matches the documented expected output **exactly**.
- [x] See the pinned upstream commit and every fixture SHA-256 printed by the
      run itself, not merely asserted in prose.
- [x] Read a graded findings document that separates real conformance gaps from
      open questions.
- [x] Read this charter and the funds ledger.

M0 explicitly does **not** claim: a 250-case corpus, a cross-implementation
matrix beyond the vendored reference, verification-CPU measurements, or any
wallet integration. Those are proposed work, and the proposal says so.

### M1 — reproducible baseline

Accepted when the corpus reaches **75 categorized adversarial cases** (currently
27), each carrying an expected result, a specification citation, and a minimized
reproducer; a written threat model and coordinated-disclosure policy are
published; and a clean clone passes on every cell of the CI matrix while
recording the BIP commit, fixture hashes, platform, and test count.

Acceptance for later milestones is defined in the proposal's milestone table and
will be restated here as each is entered.

## 6. Coordinated disclosure

Pin and reproduce, minimize to a standalone reproducer, notify maintainers
privately with the affected version and a suggested regression test, allow a
reasonable remediation window, publish facts only, then re-run the entire corpus
and preserve before/after evidence. A compatibility bug is never converted into a
claim that Bitcoin is broken.

## 7. Amendment

This charter is versioned with the repository. Any change to scope, exclusions,
or acceptance criteria is a commit with a rationale, not a silent edit.
