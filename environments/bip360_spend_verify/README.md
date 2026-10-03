# bip360-spend-verify

A verifiable tool-use environment: given one Bitcoin BIP 360 (Pay-to-Merkle-Root) script-path spend, the model must decide whether consensus accepts it and name the first rule it breaks. It gets the rules and one tool (`tagged_hash`) and has to carry out the validation walk itself.

**Why it is interesting.** Following a consensus rule exactly, in order, over many hashing steps, is where models (and human implementers) slip. The invalid cases are not random noise; they come from real bug classes this lab found in BIP 360 implementations:

| Reason code | What breaks | Where it came from |
|---|---|---|
| `bad_control_length` | control block not `1 + 32*m` bytes | spec length rule |
| `depth_exceeds_128` | `m > 128` | the reference implementation could mint these (fixed in [bitcoin/bips#2273](https://github.com/bitcoin/bips/pull/2273)); bitcoinjs-lib PR #2312 still builds a 129-deep spend |
| `bad_parity` | control byte's low bit is 0 | BIP 360 has no key path, so parity must be 1 |
| `root_mismatch` | recomputed root != q | padded zero element, flipped path or script byte, wrong leaf version, wrong program |
| `valid` | none | |

Ground truth comes from `p2mr.py`, the lab's independent implementation, which agrees byte for byte with all official BIP 360 vectors and with the reference on 2,000 random trees. `test_generator.py` also runs a literal reading of the system prompt against every label, so the prompt is provably complete.

**Reward.** 0.7 for the exact reason code, 0.3 for the right valid/invalid verdict. Answer format: `<answer>REASON</answer>`.

**Arguments.** `num_train` (1000), `num_eval` (200), `max_leaves` (6), `max_turns` (24). Train and eval use different seeds.

```
python test_generator.py
uv run vf-eval bip360-spend-verify -n 20
```

Author: [let-the-dreamers-rise](https://github.com/let-the-dreamers-rise).
