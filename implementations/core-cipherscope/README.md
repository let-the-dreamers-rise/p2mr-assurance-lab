# Bitcoin Core + CipherScope P2MR patches: conformance results

Target: Bitcoin Core v31.1 (`9be056a`) with [duncan0k/bitcoin-p2mr-patches](https://github.com/duncan0k/bitcoin-p2mr-patches)
at `522bad2` (2026-10-11), M0 consensus series plus M0.5 wallet series (34 patches,
checksums verified against the repo's `SHA256SUMS` files). Adapter and build steps:
`conformance/adapters/core-p2mr/`.

## Result (run 2026-10-11)

**231 of 231 cases pass.**

| Group | Result | What ran |
|---|---|---|
| official | 8/8 | BIP 360 construction vectors through the patched `TaprootBuilder` |
| boundary | 7/7 | depth 128 built and depth 129 rejected by `TaprootBuilder::ValidDepths`; duplicate leaves, even non-`0xc0` versions (including `0x00`) and an empty script built correctly |
| random | 200/200 | seeded random trees, byte-for-byte scriptPubKey, address and every control block |
| spend | 16/16 | consensus `VerifyScript` accepts honest spends at m = 0 and m = 128 and a `0x00` leaf; rejects m = 129, an appended zero element, wrong lengths, a zero parity bit (with its own error, `Last bit of P2MR control block first byte must be 1`), a wrong leaf version, reversed path order, an uncommitted script and a foreign program |

Which code made each rejection:

| Case | Rejected by |
|---|---|
| depth 129 | Core's `TaprootBuilder::ValidDepths` |
| empty tree, leaf version `0xc1`, three-child branch | the adapter (see the adapter README) |
| every spend rejection | the patched consensus `VerifyScript` |

Note: the series' `tmr()` descriptor refuses single-leaf trees on purpose, because
their m = 0 control block means the leaf script is never executed. The builder and
consensus both handle m = 0 as BIP 360 specifies, and so does this run.

Scope: output construction and script-path spend validation. Not covered: the M1
`OP_CHECKMLDSA44` and M2 series, wallet signing, PSBT, descriptors, policy and relay.

> BIP 360 is a Draft and is not activated on Bitcoin mainnet. Passing this pack is
> conformance evidence, not a security review or a claim of mainnet readiness.
