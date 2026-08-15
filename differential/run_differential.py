"""Differential testing: this lab's independent implementation versus the
official BIP 360 reference implementation, both pinned.

Usage: python differential/run_differential.py   (from the repository root)

Three sections:
  1. Agreement on every official construction vector in both fixtures.
  2. Agreement on seeded randomized script trees (property fuzzing).
  3. Reproduction of documented divergences (see FINDINGS.md) -- places where
     the reference implementation and the specification part ways.

Exit code 0 only if agreement holds everywhere it should and every documented
divergence reproduces exactly as recorded.
"""

import importlib.util
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import p2mr as lab
from p2mr import P2MRError
from pinning import load_manifest, load_pinned, load_pinned_json


def fail(msg: str):
    print(f"FAIL: {msg}")
    sys.exit(1)


def load_reference_module():
    """Import the vendored reference implementation, pin-checked first."""
    load_pinned("differential/upstream/p2mr_ref.py")  # hash gate
    spec = importlib.util.spec_from_file_location(
        "p2mr_ref", os.path.join(HERE, "upstream", "p2mr_ref.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def get_tree(given):
    if "scriptTree" in given:
        return given["scriptTree"]
    if "script_tree" in given:
        return given["script_tree"]
    return None


# ---------------------------------------------------------------------------
# Section 1: agreement on the official vectors
# ---------------------------------------------------------------------------

def agreement_on_vectors(ref, fixture_path):
    fixture = load_pinned_json(fixture_path)
    checked = 0
    for vector in fixture["test_vectors"]:
        expected = vector.get("expected", {})
        if "error" in expected:
            continue  # misuse vectors: the reference has no refusal path to compare
        tree = get_tree(vector["given"])
        mine = lab.construct_p2mr(tree)

        ref_leaves = [h.hex() for h in ref.collect_leaf_hashes(tree)]
        ref_root = ref.compute_merkle_root(tree).hex()
        ref_controls = [c.hex() for c in ref.collect_control_blocks(tree)]
        ref_addr = ref.encode(hrp="bc", witver=2, witprog=ref.s2w(ref_root))

        mine_leaves = [h.hex() for h in mine["leaf_hashes"]]
        assert mine_leaves == ref_leaves, f"{vector['id']}: leaf hash disagreement"
        assert mine["merkle_root"].hex() == ref_root, f"{vector['id']}: root disagreement"
        assert [c.hex() for c in mine["control_blocks"]] == ref_controls, (
            f"{vector['id']}: control block disagreement"
        )
        assert mine["address"] == ref_addr, f"{vector['id']}: address disagreement"
        checked += 1
        print(f"  AGREE  {vector['id']}")
    return checked


# ---------------------------------------------------------------------------
# Section 2: agreement on randomized trees (seeded)
# ---------------------------------------------------------------------------

FUZZ_SEED = 360
FUZZ_ITERATIONS = 2000


def random_tree(rng, max_leaves=12):
    """Random binary script tree inside the domain both implementations support:
    non-empty scripts, even leaf versions, modest depth."""
    n = rng.randint(1, max_leaves)

    def leaf():
        script = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 64)))
        version = rng.choice([0xC0, 0xC0, 0xC0, 0xC2, 0xFA])  # bias to standard
        return {"script": script.hex(), "leafVersion": version}

    nodes = [leaf() for _ in range(n)]
    while len(nodes) > 1:
        i = rng.randrange(len(nodes) - 1)
        nodes[i: i + 2] = [[nodes[i], nodes[i + 1]]]
    return nodes[0]


def agreement_fuzz(ref):
    rng = random.Random(FUZZ_SEED)
    for i in range(FUZZ_ITERATIONS):
        tree = random_tree(rng)
        mine = lab.construct_p2mr(tree)
        ref_root = ref.compute_merkle_root(tree)
        assert mine["merkle_root"] == ref_root, f"iteration {i}: root disagreement"
        ref_controls = ref.collect_control_blocks(tree)
        assert mine["control_blocks"] == ref_controls, f"iteration {i}: control disagreement"
        ref_addr = ref.encode(hrp="bc", witver=2, witprog=list(ref_root))
        assert mine["address"] == ref_addr, f"iteration {i}: address disagreement"
        # Spend-side self-check on a random leaf, lab-side.
        _, leaves = lab.parse_script_tree(tree)
        pick = rng.randrange(len(leaves))
        lab.validate_script_path(
            ref_root,
            bytes.fromhex(leaves[pick]["node"]["script"]),
            mine["control_blocks"][pick],
        )
    return FUZZ_ITERATIONS


# ---------------------------------------------------------------------------
# Section 3: documented divergences (each must reproduce exactly)
# ---------------------------------------------------------------------------

def divergence_empty_script(ref):
    """F1: consensus-valid empty-script leaves are unconstructable by the reference."""
    tree = [{"script": "", "leafVersion": 0xC0}, {"script": "51", "leafVersion": 0xC0}]
    mine = lab.construct_p2mr(tree)  # lab constructs it fine
    _, leaves = lab.parse_script_tree(tree)
    lab.validate_script_path(mine["merkle_root"], b"", mine["control_blocks"][0])
    try:
        ref.compute_merkle_root(tree)
    except ValueError:
        return f"lab root {mine['merkle_root'].hex()[:16]}...; reference raises ValueError"
    raise AssertionError("reference implementation now accepts empty scripts -- update FINDINGS")


def divergence_depth_limit(ref):
    """F2: the reference constructs control blocks consensus must reject (m > 128)."""
    tree = {"script": "51", "leafVersion": 0xC0}
    for i in range(129):
        tree = [tree, {"script": f"5{(i % 9) + 1}", "leafVersion": 0xC0}]
    try:
        lab.construct_p2mr(tree)
        raise AssertionError("lab accepted a depth-129 tree -- lab bug")
    except P2MRError:
        pass  # lab refuses at construction, as consensus spendability requires
    control = ref.compute_control_block(0, tree)  # reference emits it happily
    m = (len(control) - 1) // 32
    root = ref.compute_merkle_root(tree)
    try:
        lab.validate_script_path(root, bytes.fromhex("51"), control)
        raise AssertionError("consensus walk accepted m=129 -- lab bug")
    except P2MRError:
        pass  # the emitted control block fails the consensus length rule
    return f"reference emits {len(control)}-byte control block (m={m}); consensus limit is m=128"


def divergence_ternary_branch(ref):
    """F4: assert-based structure checks crash instead of refusing; stripped under -O."""
    tree = [
        {"script": "51", "leafVersion": 0xC0},
        {"script": "52", "leafVersion": 0xC0},
        {"script": "53", "leafVersion": 0xC0},
    ]
    try:
        lab.construct_p2mr(tree)
        raise AssertionError("lab accepted a ternary branch -- lab bug")
    except P2MRError:
        pass  # clean domain error
    try:
        ref.compute_merkle_root(tree)
    except AssertionError:
        return "lab raises P2MRError; reference raises bare AssertionError (stripped under python -O)"
    except ValueError:
        raise AssertionError("reference now refuses cleanly -- update FINDINGS")
    raise AssertionError("reference accepted a ternary branch outright -- worse than documented")


def divergence_odd_leaf_version(ref):
    """F3: the reference silently masks odd leaf versions; the lab refuses them."""
    odd = {"script": "51", "leafVersion": 0xC1}
    even = {"script": "51", "leafVersion": 0xC0}
    try:
        lab.construct_p2mr(odd)
        raise AssertionError("lab accepted an odd leaf version -- lab bug")
    except P2MRError:
        pass
    silent = ref.compute_merkle_root(odd)
    proper = ref.compute_merkle_root(even)
    assert silent == proper, "reference no longer masks silently -- update FINDINGS"
    return "reference silently coerces leafVersion 0xc1 to 0xc0; lab refuses with a domain error"


DIVERGENCES = [
    ("F1 empty-script leaf unconstructable by reference", divergence_empty_script),
    ("F2 no depth limit: consensus-invalid control blocks emitted", divergence_depth_limit),
    ("F4 assert-based structure validation", divergence_ternary_branch),
    ("F3 silent odd leaf-version masking", divergence_odd_leaf_version),
]


def main():
    manifest = load_manifest()
    ref = load_reference_module()

    print("Section 1: agreement on official construction vectors")
    n_std = agreement_on_vectors(ref, "vectors/p2mr_construction.json")
    n_pqc = agreement_on_vectors(ref, "vectors/p2mr_pqc_construction.json")

    print("Section 2: agreement on randomized trees")
    n_fuzz = agreement_fuzz(ref)
    print(f"  AGREE  {n_fuzz} seeded random trees (seed {FUZZ_SEED})")

    print("Section 3: documented divergences (FINDINGS.md)")
    reproduced = 0
    for name, demo in DIVERGENCES:
        try:
            note = demo(ref)
        except AssertionError as e:
            fail(f"divergence '{name}': {e}")
        print(f"  REPRODUCED  {name}\n              {note}")
        reproduced += 1

    print()
    print(f"{n_std + n_pqc}/{n_std + n_pqc} official construction vectors: full agreement with the reference implementation")
    print(f"{n_fuzz}/{n_fuzz} randomized trees: full agreement (seed {FUZZ_SEED})")
    print(f"{reproduced}/{len(DIVERGENCES)} documented divergences reproduced -- details in FINDINGS.md")
    print(f"pinned: bitcoin/bips @ {manifest['upstream_commit']}")


if __name__ == "__main__":
    main()
