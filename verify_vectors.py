"""Run the official BIP 360 P2MR construction vectors plus local boundary tests.

Usage: python verify_vectors.py

Exit code 0 only if every check passes. The fixture is refused unless its
SHA-256 matches the pin recorded in vectors/MANIFEST.json -- results against an
unpinned or altered fixture are meaningless and are not produced.
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


def load_pinned_fixture():
    manifest_path = os.path.join(HERE, "vectors", "MANIFEST.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    fixture_path = os.path.join(HERE, "vectors", manifest["fixture"])
    with open(fixture_path, "rb") as f:
        raw = f.read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != manifest["sha256"]:
        fail(
            "fixture hash mismatch -- refusing to run against an unpinned fixture\n"
            f"  expected: {manifest['sha256']}\n"
            f"  actual:   {digest}"
        )
    return manifest, json.loads(raw.decode("utf-8"))


def get_tree(given):
    if "scriptTree" in given:
        return given["scriptTree"]
    if "script_tree" in given:
        return given["script_tree"]
    return None


def check_vector(vector) -> str:
    """Run one official vector; returns a short note, raises AssertionError on mismatch."""
    given = vector.get("given", {})
    intermediary = vector.get("intermediary", {})
    expected = vector.get("expected", {})
    tree = get_tree(given)

    if "error" in expected:
        # Misuse vectors: the constructor must refuse, with the specified reason.
        try:
            p2mr.construct_p2mr(tree, internal_pubkey=given.get("internalPubkey"))
        except P2MRError as e:
            assert str(e) == expected["error"], (
                f"error message mismatch: got {str(e)!r}, want {expected['error']!r}"
            )
        else:
            raise AssertionError("constructor accepted input the spec defines as invalid")

        # The internal-pubkey misuse vector additionally documents the P2TR-style
        # tweak a faulty implementation would compute; verify those bytes too.
        if given.get("internalPubkey"):
            pubkey = bytes.fromhex(given["internalPubkey"])
            tweak, tweaked = p2mr.taproot_tweak(pubkey)
            if "tweak" in intermediary:
                assert tweak.hex() == intermediary["tweak"], "documented tweak mismatch"
            if "tweakedPubkey" in intermediary:
                assert tweaked.hex() == intermediary["tweakedPubkey"], (
                    "documented tweaked pubkey mismatch"
                )
            if "scriptPubKey" in expected:
                wrong_spk = bytes([0x52, 0x20]) + tweaked
                assert wrong_spk.hex() == expected["scriptPubKey"], (
                    "documented misconstruction scriptPubKey mismatch"
                )
            return "misuse refused; documented wrong-path bytes verified"
        return "misuse refused with the specified error"

    result = p2mr.construct_p2mr(tree)

    if "leafHashes" in intermediary:
        got = [h.hex() for h in result["leaf_hashes"]]
        assert got == intermediary["leafHashes"], (
            f"leaf hashes mismatch:\n  got:  {got}\n  want: {intermediary['leafHashes']}"
        )
    if "merkleRoot" in intermediary and intermediary["merkleRoot"] is not None:
        assert result["merkle_root"].hex() == intermediary["merkleRoot"], "merkle root mismatch"
    if "scriptPubKey" in expected:
        assert result["script_pubkey"].hex() == expected["scriptPubKey"], "scriptPubKey mismatch"
    if "bip350Address" in expected:
        assert result["address"] == expected["bip350Address"], (
            f"address mismatch: got {result['address']}, want {expected['bip350Address']}"
        )
    if "scriptPathControlBlocks" in expected:
        got = [c.hex() for c in result["control_blocks"]]
        assert got == expected["scriptPathControlBlocks"], (
            f"control blocks mismatch:\n  got:  {got}\n  want: {expected['scriptPathControlBlocks']}"
        )

    # Spend-side self-check: every leaf's (script, control block) pair must walk
    # back to the committed witness program per the BIP 360 validation rules.
    program = p2mr.parse_script_pubkey(result["script_pubkey"])
    _, leaves = p2mr.parse_script_tree(tree)
    for leaf, control in zip(leaves, result["control_blocks"]):
        script = bytes.fromhex(leaf["node"]["script"])
        p2mr.validate_script_path(program, script, control)

    return f"{len(result['leaf_hashes'])} leaf(s); construction + spend-side walk verified"


# ---------------------------------------------------------------------------
# Local boundary tests -- edges the official vectors do not exercise
# ---------------------------------------------------------------------------

def boundary_compact_size_edges():
    """CompactSize encoding boundaries used by ser_script (252/253, 16-bit/32-bit)."""
    assert p2mr.compact_size(252) == b"\xfc"
    assert p2mr.compact_size(253) == b"\xfd\xfd\x00"
    assert p2mr.compact_size(0xFFFF) == b"\xfd\xff\xff"
    assert p2mr.compact_size(0x10000) == b"\xfe\x00\x00\x01\x00"
    a = p2mr.leaf_hash(0xC0, b"\x51" * 252)
    b = p2mr.leaf_hash(0xC0, b"\x51" * 253)
    assert a != b


def boundary_odd_leaf_version_rejected():
    """Leaf versions carry the parity flag in bit 0; odd versions must be refused."""
    try:
        p2mr.leaf_hash(0xC1, b"\x51")
    except P2MRError:
        return
    raise AssertionError("odd leaf version was accepted")


def boundary_depth_limit():
    """Validation walk accepts m = 128 and refuses m = 129 (BIP 360: m in [0, 128])."""
    script = b"\x51"
    path = [p2mr.sha256(bytes([i])) for i in range(128)]
    control = bytes([0xC1]) + b"".join(path)
    k = p2mr.leaf_hash(0xC0, script)
    for e in path:
        k = p2mr.branch_hash(k, e)
    assert p2mr.validate_script_path(k, script, control)
    too_deep = control + p2mr.sha256(b"one more")
    try:
        p2mr.validate_script_path(k, script, too_deep)
    except P2MRError:
        return
    raise AssertionError("depth 129 control block was accepted")


def boundary_branch_commutativity():
    """TapBranch sorts its pair: branch(a, b) == branch(b, a)."""
    a = p2mr.sha256(b"a")
    b = p2mr.sha256(b"b")
    assert p2mr.branch_hash(a, b) == p2mr.branch_hash(b, a)
    assert p2mr.branch_hash(a, b) != p2mr.branch_hash(a, p2mr.sha256(b"c"))


def boundary_bech32m_round_trip():
    """Encode/decode round trip, and a corrupted character must fail the checksum."""
    root = p2mr.sha256(b"round trip")
    addr = p2mr.bech32m_encode("bc", 2, root)
    hrp, witver, program = p2mr.bech32m_decode(addr)
    assert (hrp, witver, program) == ("bc", 2, root)
    corrupted = addr[:-1] + ("q" if addr[-1] != "q" else "p")
    try:
        p2mr.bech32m_decode(corrupted)
    except P2MRError:
        return
    raise AssertionError("corrupted address passed checksum")


def boundary_program_length():
    """The witness program is exactly 32 bytes; 31 and 33 must be refused."""
    for n in (31, 33):
        try:
            p2mr.make_script_pubkey(b"\x00" * n)
        except P2MRError:
            continue
        raise AssertionError(f"{n}-byte witness program was accepted")
    assert len(p2mr.make_script_pubkey(b"\x00" * 32)) == 34


def boundary_segwit_version_discrimination():
    """A v1 (P2TR-shaped) scriptPubKey must not parse as P2MR."""
    root = p2mr.sha256(b"version test")
    try:
        p2mr.parse_script_pubkey(bytes([0x51, 0x20]) + root)
    except P2MRError:
        pass
    else:
        raise AssertionError("SegWit v1 output parsed as P2MR")
    assert p2mr.parse_script_pubkey(bytes([0x52, 0x20]) + root) == root


def boundary_control_block_reconstruction():
    """Every leaf of a fresh 3-leaf tree must walk back to the committed root."""
    tree = [
        {"script": "51", "leafVersion": 0xC0},
        [
            {"script": "52", "leafVersion": 0xC0},
            {"script": "53", "leafVersion": 0xC0},
        ],
    ]
    result = p2mr.construct_p2mr(tree)
    program = p2mr.parse_script_pubkey(result["script_pubkey"])
    _, leaves = p2mr.parse_script_tree(tree)
    for leaf, control in zip(leaves, result["control_blocks"]):
        p2mr.validate_script_path(program, bytes.fromhex(leaf["node"]["script"]), control)


BOUNDARY_TESTS = [
    ("compact_size_encoding_edges", boundary_compact_size_edges),
    ("odd_leaf_version_rejected", boundary_odd_leaf_version_rejected),
    ("merkle_depth_limit_128", boundary_depth_limit),
    ("tapbranch_commutativity", boundary_branch_commutativity),
    ("bech32m_round_trip_and_checksum", boundary_bech32m_round_trip),
    ("witness_program_length_strict", boundary_program_length),
    ("segwit_version_discrimination", boundary_segwit_version_discrimination),
    ("control_block_reconstruction", boundary_control_block_reconstruction),
]


def main():
    manifest, fixture = load_pinned_fixture()
    vectors = fixture["test_vectors"]

    passed = 0
    for vector in vectors:
        try:
            note = check_vector(vector)
        except (AssertionError, P2MRError, KeyError) as e:
            fail(f"vector {vector.get('id', '?')}: {e}")
        print(f"  PASS  {vector['id']}  ({note})")
        passed += 1

    boundary_passed = 0
    for name, test in BOUNDARY_TESTS:
        try:
            test()
        except (AssertionError, P2MRError) as e:
            fail(f"boundary test {name}: {e}")
        print(f"  PASS  boundary: {name}")
        boundary_passed += 1

    print()
    print(f"{passed}/{len(vectors)} official BIP 360 construction vectors PASS (byte-for-byte)")
    print(f"{boundary_passed}/{len(BOUNDARY_TESTS)} local boundary tests PASS")
    print(f"pinned: bitcoin/bips @ {manifest['upstream_commit']}")
    print(f"fixture: {manifest['fixture']}")
    print(f"sha256:  {manifest['sha256']}")


if __name__ == "__main__":
    main()
