# btq-core P2MR: conformance results

Target: [btq-ag/btq-core](https://github.com/btq-ag/btq-core) at commit `5d18dd6`
(2026-10-10). Adapter and build steps: `conformance/adapters/btq-core/`.

## Result (run 2026-10-10)

**231 of 231 cases pass.**

| Group | Result | What ran |
|---|---|---|
| official | 8/8 | BIP 360 construction vectors through `P2MRBuilder` |
| boundary | 7/7 | depth 128 built; depth 129 and leaf version `0xc1` rejected by btq-core's own wallet-entry checks; duplicate leaves, even non-`0xc0` versions (including `0x00`) and an empty script built correctly |
| random | 200/200 | seeded random trees, byte-for-byte scriptPubKey, address and every control block |
| spend | 16/16 | consensus `VerifyScript` accepts honest spends at m = 0 and m = 128 and a `0x00` leaf; rejects m = 129, a 32-byte zero element appended, wrong lengths, a zero parity bit, a wrong leaf version, reversed path order, an uncommitted script and a foreign program |

Which code made each rejection:

| Case | Rejected by |
|---|---|
| empty tree, depth 129, leaf version `0xc1` | btq-core's `BuildP2MRTreeChecked` checks (copied into the adapter) |
| three-child branch | the adapter's tree flattening (btq-core takes a depth list) |
| every spend rejection | btq-core consensus: `Invalid Taproot control block size` or `Witness program hash mismatch` |

This agrees with an earlier read of commit `f1ebbdd`: btq-core handles every bug class the lab has
found elsewhere, including the leaf-version-`0x00` bug found in bitcoinjs-lib.

Scope: this run covers output construction and script-path spend validation. It
does not cover btq-core's Dilithium signature opcodes, wallet, PSBT or RPC layers.

> BIP 360 is a Draft and is not activated on Bitcoin mainnet. Passing this pack is
> conformance evidence, not a security review or a claim of mainnet readiness.
