"""Checks the generator against the lab's validator and the official vectors' rules."""
from collections import Counter

from bip360_spend_verify import REASONS, expected_reason, generate_tasks


def test_labels_are_exhaustive_and_balanced():
    rows = generate_tasks(700)
    c = Counter(r["answer"] for r in rows)
    assert set(c) <= set(REASONS)
    assert all(c[r] > 30 for r in REASONS), c


def test_labels_recompute():
    for r in generate_tasks(300, seed=7):
        q, s, cb = (bytes.fromhex(line.split(": ", 1)[1]) for line in r["question"].splitlines())
        assert expected_reason(q, s, cb) == r["answer"]


def test_vendored_p2mr_matches_root():
    import pathlib
    here = pathlib.Path(__file__).parent
    root = here.parent.parent / "p2mr.py"
    if root.exists():
        assert (here / "p2mr.py").read_bytes() == root.read_bytes()


def test_deterministic():
    assert generate_tasks(50) == generate_tasks(50)



def _oracle(q, s, c):
    """Follows SYSTEM_PROMPT literally, using only the tool, to prove the prompt is complete."""
    from bip360_spend_verify import tagged_hash
    if len(c) < 1 or (len(c) - 1) % 32:
        return "bad_control_length"
    m = (len(c) - 1) // 32
    if m > 128:
        return "depth_exceeds_128"
    if c[0] & 1 != 1:
        return "bad_parity"
    k = bytes.fromhex(tagged_hash("TapLeaf", bytes([c[0] & 0xFE, len(s)]).hex() + s.hex()))
    for j in range(m):
        e = c[1 + 32 * j:33 + 32 * j]
        k = bytes.fromhex(tagged_hash("TapBranch", (min(k, e) + max(k, e)).hex()))
    return "valid" if k == q else "root_mismatch"


def test_prompt_rules_match_ground_truth():
    for r in generate_tasks(400, seed=11):
        q, s, cb = (bytes.fromhex(line.split(": ", 1)[1]) for line in r["question"].splitlines())
        assert _oracle(q, s, cb) == r["answer"], r


if __name__ == "__main__":
    test_labels_are_exhaustive_and_balanced(); test_labels_recompute(); test_deterministic(); test_vendored_p2mr_matches_root(); test_prompt_rules_match_ground_truth()
    print(Counter(r["answer"] for r in generate_tasks(700)))
    print("generator OK")
