"""Generate conformance/vectors.json, the portable P2MR conformance pack.

Every expected value is computed by this lab's p2mr.py, which agrees byte for
byte with the pinned BIP 360 reference implementation on all official vectors
and 2000 random trees (see differential/run_differential.py and FINDINGS.md).
The official vectors are additionally checked against their own published
expected values before they are written, so the pack cannot drift from them.

Run:  python conformance/gen_vectors.py   (deterministic; output is committed)
"""
import hashlib
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import p2mr  # noqa: E402

UPSTREAM = json.load(open(os.path.join(ROOT, "vectors", "MANIFEST.json")))["upstream_commit"]


def ok_case(cid, group, tree, note):
    r = p2mr.construct_p2mr(tree)
    return {
        "id": cid,
        "group": group,
        "note": note,
        "script_tree": tree,
        "expect": {
            "script_pubkey": r["script_pubkey"].hex(),
            "address": r["address"],
            "control_blocks": [c.hex() for c in r["control_blocks"]],
        },
    }


def reject_case(cid, group, tree, note):
    try:
        p2mr.construct_p2mr(tree)
    except p2mr.P2MRError as e:
        return {"id": cid, "group": group, "note": note, "script_tree": tree,
                "expect": {"reject": True, "oracle_error": str(e)}}
    raise SystemExit(f"oracle accepted {cid}, which the pack expects to be rejected")


def leaf(script_hex, version=0xC0):
    return {"script": script_hex, "leafVersion": version}


def chain(depth):
    """A tree whose deepest leaf sits at exactly `depth`."""
    node = leaf("51")
    for i in range(depth):
        node = [node, leaf(f"{i + 1:04x}")]
    return node


cases = []

# 1. Official BIP 360 construction vectors that take only a script tree.
official = json.load(open(os.path.join(ROOT, "vectors", "p2mr_construction.json")))["test_vectors"]
for v in official:
    g = v["given"]
    if "internalPubkey" in g:
        continue  # API-specific (an internal key argument); not portable
    tree = g.get("scriptTree", g.get("script_tree"))
    if not tree:
        cases.append(reject_case(v["id"], "official", tree if tree is not None else "",
                                 v["objective"]))
        continue
    c = ok_case(v["id"], "official", tree, v["objective"])
    e = v["expected"]
    assert c["expect"]["script_pubkey"] == e["scriptPubKey"], v["id"]
    assert c["expect"]["address"] == e["bip350Address"], v["id"]
    assert c["expect"]["control_blocks"] == e["scriptPathControlBlocks"], v["id"]
    cases.append(c)

# 2. Boundary cases from the BIP 360 text.
cases.append(ok_case("depth_128_accepted", "boundary", chain(128),
                     "deepest leaf at m = 128, the maximum the spec allows"))
cases.append(reject_case("depth_129_rejected", "boundary", chain(129),
                         "m = 129 exceeds the 128-level bound (bitcoin/bips#2273)"))
cases.append(reject_case("odd_leaf_version_rejected", "boundary", leaf("51", 0xC1),
                         "leaf versions must be even; 0xc1 must not be silently coerced"))
cases.append(reject_case("three_child_branch_rejected", "boundary",
                         [leaf("51"), leaf("52"), leaf("53")],
                         "a branch has exactly two children"))
cases.append(ok_case("duplicate_leaves", "boundary", [leaf("51"), [leaf("52"), leaf("51")]],
                     "the same script twice; each DFS position gets its own control block"))
cases.append(ok_case("non_default_leaf_versions", "boundary",
                     [leaf("51", 0xC2), [leaf("52", 0xFA), leaf("53", 0x00)]],
                     "even non-0xc0 leaf versions are valid and change the leaf hash"))
cases.append(ok_case("empty_script_leaf", "boundary", leaf(""),
                     "a zero-length script is a valid leaf"))

# 3. Seeded random trees (seed 360, same generator family as the differential run).
rng = random.Random(360)


def rtree(d):
    if d == 0 or rng.random() < 0.3:
        n = rng.randint(0, 60)
        v = rng.choice([0xC0, 0xC0, 0xC0, 0xC2, 0xFA])
        return leaf(bytes(rng.getrandbits(8) for _ in range(n)).hex(), v)
    return [rtree(d - 1), rtree(d - 1)]


for i in range(200):
    cases.append(ok_case(f"random_{i:03d}", "random", rtree(rng.randint(0, 7)),
                         "seeded random tree (seed 360)"))

# 4. Spend validation: (witness program, leaf script, control block) triples that
#    a node or validator must accept or reject under BIP 360's validation rules.
def spend(cid, program, script, control, valid, note):
    try:
        p2mr.validate_script_path(program, script, control)
        oracle = True
    except p2mr.P2MRError as e:
        oracle = str(e)
    if (oracle is True) != valid:
        raise SystemExit(f"oracle disagrees with the intended outcome for {cid}: {oracle}")
    expect = {"valid": True} if valid else {"reject": True, "oracle_error": oracle}
    return {"id": cid, "group": "spend", "note": note,
            "spend": {"program": program.hex(), "script": script.hex(),
                      "control": control.hex()},
            "expect": expect}


def leaf_spends(tree):
    root, leaves = p2mr.parse_script_tree(tree)
    out = []
    for lf in leaves:
        v = lf["node"].get("leafVersion", 0xC0)
        out.append((root, bytes.fromhex(lf["node"]["script"]),
                    bytes([v | 1]) + b"".join(lf["path"])))
    return out


Z = bytes(32)
three = [leaf("51"), [leaf("52", 0xC2), leaf("53")]]
for i, (q, s, c) in enumerate(leaf_spends(three)):
    cases.append(spend(f"spend_valid_leaf{i}", q, s, c, True,
                       "honest script-path spend of each leaf"))
q, s, c = leaf_spends(leaf("51"))[0]
cases.append(spend("spend_valid_single_leaf_m0", q, s, c, True,
                   "single-leaf tree: control block is the control byte alone (m = 0)"))
deep = leaf_spends(chain(128))[0]
cases.append(spend("spend_valid_depth_128", *deep, True, "m = 128 is the maximum allowed"))
deep = leaf_spends(chain(129))[0]
cases.append(spend("spend_reject_depth_129", *deep, False,
                   "m = 129 must be rejected even though the root would match"))
q, s, c = leaf_spends(three)[1]
cases.append(spend("spend_reject_zero_padding", q, s, c + Z, False,
                   "appending a 32-byte zero element changes the computed root; never a valid spend"))
cases.append(spend("spend_reject_trailing_byte", q, s, c + b"\x00", False,
                   "control block length must be 1 + 32*m"))
cases.append(spend("spend_reject_truncated", q, s, c[:-1], False,
                   "control block length must be 1 + 32*m"))
cases.append(spend("spend_reject_empty_control", q, s, b"", False,
                   "an empty control block is not 1 + 32*m"))
cases.append(spend("spend_reject_parity_zero", q, s, bytes([c[0] & 0xFE]) + c[1:], False,
                   "BIP 360: the control byte's low bit must be 1"))
cases.append(spend("spend_reject_wrong_leaf_version", q, s, bytes([0xC1]) + c[1:], False,
                   "control byte claims leaf version 0xc0 for a 0xc2 leaf; root mismatch"))
cases.append(spend("spend_reject_wrong_script", q, bytes.fromhex("54"), c, False,
                   "a script not committed in the tree"))
cases.append(spend("spend_reject_reversed_path", q, s,
                   c[:1] + c[33:65] + c[1:33], False,
                   "path elements are ordered leaf to root; reversing them changes the root"))
cases.append(spend("spend_reject_other_program", bytes(31) + b"\x01", s, c, False,
                   "a valid control block for a different witness program"))

pack = {
    "name": "p2mr-conformance-pack",
    "version": 2,
    "spec": "BIP 360 (Pay-to-Merkle-Root), Draft",
    "upstream_bips_commit": UPSTREAM,
    "oracle": "p2mr.py in let-the-dreamers-rise/p2mr-assurance-lab",
    "address_hrp": "bc",
    "boundary": ("BIP 360 is a Draft and is not activated on mainnet. Passing this pack "
                 "is conformance evidence, not a security review or a claim of mainnet "
                 "readiness."),
    "cases": cases,
}
out = os.path.join(HERE, "vectors.json")
data = (json.dumps(pack, separators=(",", ":")) + "\n").encode()
open(out, "wb").write(data)
groups = {}
for c in cases:
    groups[c["group"]] = groups.get(c["group"], 0) + 1
print(f"wrote {len(cases)} cases {groups}")
print(f"vectors.json sha256 {hashlib.sha256(data).hexdigest()}")
