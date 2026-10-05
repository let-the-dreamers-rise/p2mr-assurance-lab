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

pack = {
    "name": "p2mr-conformance-pack",
    "version": 1,
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
