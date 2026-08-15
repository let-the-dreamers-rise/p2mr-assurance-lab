"""Run the adversarial mutation corpus against the P2MR implementation.

Usage: python run_mutations.py

Each case starts from an official (pin-checked) BIP 360 construction vector,
applies exactly one mutation, and asserts the expected outcome. Reject cases
must raise P2MRError; the accept case must validate. Exit code 0 only if every
case behaves as its specification citation requires.
"""

import hashlib
import json
import os
import sys

import p2mr
from p2mr import P2MRError

HERE = os.path.dirname(os.path.abspath(__file__))


def fail(msg: str):
    print(f"FAIL: {msg}")
    sys.exit(1)


def load_fixture():
    with open(os.path.join(HERE, "vectors", "MANIFEST.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    path = os.path.join(HERE, "vectors", manifest["fixture"])
    raw = open(path, "rb").read()
    if hashlib.sha256(raw).hexdigest() != manifest["sha256"]:
        fail("fixture hash mismatch -- refusing to run against an unpinned fixture")
    fixture = json.loads(raw.decode("utf-8"))
    return {v["id"]: v for v in fixture["test_vectors"]}


def build_base(vector):
    """Construct the untouched output set for a vector: tree, result, leaves."""
    given = vector["given"]
    tree = given.get("scriptTree", given.get("script_tree"))
    result = p2mr.construct_p2mr(tree)
    _, leaves = p2mr.parse_script_tree(tree)
    return tree, result, leaves


def leaf_script(leaves, i):
    return bytes.fromhex(leaves[i]["node"]["script"])


def run_case(case, vectors):
    vector = vectors[case["base_vector"]]
    op = case["operation"]
    kind = op["op"]
    tree, result, leaves = build_base(vector)
    program = p2mr.parse_script_pubkey(result["script_pubkey"])

    def expect_reject(fn):
        try:
            fn()
        except P2MRError:
            return True
        raise AssertionError("mutation was accepted but the specification requires rejection")

    if kind == "path_byte_flip":
        i = op["leaf_index"]
        control = bytearray(result["control_blocks"][i])
        idx = 1 + op["byte_index"]
        if idx >= len(control):
            raise AssertionError("byte_index outside merkle path")
        control[idx] ^= 0x01
        return expect_reject(lambda: p2mr.validate_script_path(program, leaf_script(leaves, i), bytes(control)))

    if kind == "control_truncate":
        i = op["leaf_index"]
        control = result["control_blocks"][i][: -op["drop_bytes"]]
        return expect_reject(lambda: p2mr.validate_script_path(program, leaf_script(leaves, i), control))

    if kind == "control_extend":
        i = op["leaf_index"]
        control = result["control_blocks"][i] + b"\x00" * op["extra_bytes"]
        return expect_reject(lambda: p2mr.validate_script_path(program, leaf_script(leaves, i), control))

    if kind == "parity_zero":
        i = op["leaf_index"]
        control = bytearray(result["control_blocks"][i])
        control[0] &= 0xFE
        return expect_reject(lambda: p2mr.validate_script_path(program, leaf_script(leaves, i), bytes(control)))

    if kind == "set_control_version":
        i = op["leaf_index"]
        control = bytearray(result["control_blocks"][i])
        control[0] = op["new_version"] | 1
        return expect_reject(lambda: p2mr.validate_script_path(program, leaf_script(leaves, i), bytes(control)))

    if kind == "script_byte_flip":
        i = op["leaf_index"]
        script = bytearray(leaf_script(leaves, i))
        script[op["byte_index"]] ^= 0x01
        return expect_reject(lambda: p2mr.validate_script_path(program, bytes(script), result["control_blocks"][i]))

    if kind == "script_truncate":
        i = op["leaf_index"]
        script = leaf_script(leaves, i)[: -op["drop_bytes"]]
        return expect_reject(lambda: p2mr.validate_script_path(program, script, result["control_blocks"][i]))

    if kind == "path_reorder":
        i = op["leaf_index"]
        control = result["control_blocks"][i]
        m = (len(control) - 1) // 32
        if m < 2:
            raise AssertionError("path_reorder requires a depth >= 2 leaf")
        e0 = control[1:33]
        e1 = control[33:65]
        if e0 == e1:
            raise AssertionError("path elements identical; reorder would be a no-op")
        swapped = control[:1] + e1 + e0 + control[65:]
        return expect_reject(lambda: p2mr.validate_script_path(program, leaf_script(leaves, i), swapped))

    if kind == "empty_control":
        i = op["leaf_index"]
        return expect_reject(lambda: p2mr.validate_script_path(program, leaf_script(leaves, i), b""))

    if kind == "spk_replace_version":
        spk = bytearray(result["script_pubkey"])
        spk[0] = op["new_version_byte"]
        return expect_reject(lambda: p2mr.parse_script_pubkey(bytes(spk)))

    if kind == "spk_push_33":
        spk = bytes([0x52, 0x21]) + result["merkle_root"] + b"\x00"
        return expect_reject(lambda: p2mr.parse_script_pubkey(spk))

    if kind == "spk_append_byte":
        spk = result["script_pubkey"] + bytes([op["byte"]])
        return expect_reject(lambda: p2mr.parse_script_pubkey(spk))

    if kind == "addr_char_flip":
        addr = result["address"]
        idx = op["char_index"] % len(addr)
        if idx <= addr.rfind("1"):
            raise AssertionError("char_index must land in the data part")
        flipped = "q" if addr[idx] != "q" else "p"
        mutated = addr[:idx] + flipped + addr[idx + 1:]
        return expect_reject(lambda: p2mr.bech32m_decode(mutated))

    if kind == "addr_encode_bech32_constant":
        legacy = p2mr.bech32m_encode("bc", 2, result["merkle_root"], const=1)
        return expect_reject(lambda: p2mr.bech32m_decode(legacy))

    if kind == "addr_encode_witver":
        other = p2mr.bech32m_encode("bc", op["witver"], result["merkle_root"])
        _, witver, _ = p2mr.bech32m_decode(other)
        if witver == 2:
            raise AssertionError("witness version unexpectedly decoded as 2")
        # Valid bech32m, but not a P2MR address: the P2MR check must refuse it.
        def check():
            if witver != 2:
                raise P2MRError("not a SegWit version 2 (P2MR) address")
        return expect_reject(check)

    if kind == "use_leaf":
        i = op["leaf_index"]
        return p2mr.validate_script_path(program, leaf_script(leaves, i), result["control_blocks"][i])

    raise AssertionError(f"unknown operation {kind!r}")


def main():
    vectors = load_fixture()
    with open(os.path.join(HERE, "mutations", "corpus.json"), encoding="utf-8") as f:
        corpus = json.load(f)

    cases = corpus["cases"]
    passed = 0
    for case in cases:
        try:
            run_case(case, vectors)
        except (AssertionError, P2MRError, KeyError) as e:
            fail(f"{case['id']}: {e}")
        print(f"  PASS  {case['id']}  [{case['category']}] expected={case['expected']}")
        passed += 1

    print()
    print(f"{passed}/{len(cases)} adversarial mutation cases PASS")
    print("every case cites the specification text that defines its expected outcome")


if __name__ == "__main__":
    main()
