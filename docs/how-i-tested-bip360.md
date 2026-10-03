# How I found two gaps in Bitcoin's post-quantum proposal with a few hundred lines of Python

*Ashwin Goyal ([let-the-dreamers-rise](https://github.com/let-the-dreamers-rise)), October 2026*

BIP 360 adds a new output type to Bitcoin called Pay-to-Merkle-Root (P2MR). It is Taproot with the key path removed: you commit to a tree of scripts and can only spend through one of them. If large quantum computers ever arrive, a public key sitting on-chain becomes a liability, and P2MR is one of the first concrete steps toward outputs that never expose one.

A soft fork is unforgiving. If two wallets disagree on whether a spend is valid, someone's coins get stuck or someone's node forks off. So before anyone builds on a draft like this, someone should check that its reference implementation does exactly what its text says. I decided to be that someone. This is how I did it, what I found, and what I would tell anyone testing a spec.

## Step 1: write a second implementation from the text alone

The point of an independent implementation is that it does not share the reference's mistakes. So I did not read the reference code first. I built [`p2mr.py`](../p2mr.py) from the BIP text, plus the BIP 341 machinery it points to: tagged hashes, sorted branch pairs, compact-size script serialization, and bech32m addresses. No dependencies, so anyone can run it in seconds.

Two rules carried most of the weight:

- A control block must be `1 + 32*m` bytes, with `m` between 0 and 128.
- The low bit of the first byte must be 1, because P2MR has no key path.

## Step 2: prove the two implementations agree before trusting any disagreement

A differential test is only useful if a mismatch means something. So the first job was a control: run both implementations on every official test vector and on 2,000 random script trees with a fixed seed, and require byte-for-byte agreement on the merkle root, every control block and the address.

They agreed on all of it. That matters more than any single finding. It tells you the independent version is right on the shared ground, so where they do diverge, the divergence is a signal and not a bug in the new code.

## Step 3: push both past the edges the vectors cover

Official vectors test the happy path. Bugs live at the boundaries, so I generated cases the vectors never touch:

- **Trees deeper than 128.** The spec says no valid spend can have `m > 128`. The reference implementation happily built a 4,129-byte control block for a 129-deep tree. That is an output consensus would reject: coins sent there could never be spent. The fix was a depth check at construction time.
- **Validation with `assert`.** The reference checked that every tree branch has exactly two children using Python's `assert`. Run Python with `-O` and assertions disappear, so a malformed three-child branch silently produced a wrong merkle root instead of an error. The fix was an explicit exception.

Both went upstream as one pull request. BIP editor Jon Atack ACKed it and it was merged as [bitcoin/bips#2273](https://github.com/bitcoin/bips/pull/2273).

Two other divergences were not bugs. The reference refuses empty scripts and silently masks odd leaf versions; my version does the opposite on both. Each is a defensible choice, so I sent them to the authors as questions instead of calling them defects. Grading findings honestly is what gets maintainers to keep reading your reports.

## Step 4: make every expectation cite the spec

On top of the differential test sits a mutation corpus of 27 cases. Each one takes an official vector, changes exactly one thing (a flipped path byte, a cleared parity bit, an extra 32 zero bytes), and states the expected result with the sentence of the BIP that requires it. When a test fails, nobody has to argue about whether the test is right: the citation is right there.

## Step 5: point it at the next implementation

Once the suite existed, testing someone else's code took an afternoon. I ran it against bitcoinjs-lib's P2MR pull request: 2,006 of 2,007 cases agreed. The one that did not was a duplicate-leaf tree where it picked the deeper of two identical leaves, giving a valid but 32-byte heavier spend. A separate probe showed it would also build a 129-deep spend that its own validator then rejected, the same class of bug the reference had.

## What I would tell anyone testing a spec

1. **Build from the text, not the code.** Shared assumptions are invisible to a test that inherits them.
2. **Establish agreement first.** A thousand matching cases is what makes the one mismatch credible.
3. **Test the numbers in the spec.** Every limit (128, 32, "exactly two") is a boundary someone forgot to enforce somewhere.
4. **Cite the rule in every test.** It turns "I think this is wrong" into "the spec says this, and here is the line."
5. **Grade your findings honestly.** Calling a design choice a bug costs you the maintainer's attention for the real ones.

Everything here runs offline in about ten minutes: [p2mr-assurance-lab](https://github.com/let-the-dreamers-rise/p2mr-assurance-lab). The same findings now also form an RL environment that tests whether a model can apply these rules step by step ([`environments/bip360_spend_verify`](../environments/bip360_spend_verify)).
