"""bip360-spend-verify: can a model follow a Bitcoin consensus rule exactly?

Each task is one BIP 360 (P2MR) script-path spend: a 32-byte witness program q,
a leaf script, and a control block. The model must decide whether the spend
passes the BIP 360 script-validation walk and, if not, name the first rule it
breaks. It gets one tool, tagged_hash, and has to do the walk itself.

Ground truth comes from p2mr.validate_script_path, the independent
implementation whose findings were upstreamed in bitcoin/bips#2273. Invalid
cases are drawn from real bug classes: over-depth control blocks (the reference
once minted these), padded control blocks, broken parity bits, flipped path or
script bytes, and malformed lengths.
"""

import hashlib
import random

# p2mr.py is a byte-identical copy of the lab's root p2mr.py (checked by test_generator.py).
from p2mr import MAX_MERKLE_DEPTH, P2MRError, construct_p2mr, validate_script_path
from p2mr import tagged_hash as _tagged_hash

REASONS = [
    "valid",
    "bad_control_length",   # len(c) != 1 + 32*m
    "depth_exceeds_128",    # m > 128
    "bad_parity",           # c[0] & 1 != 1
    "root_mismatch",        # recomputed root != q
]

SYSTEM_PROMPT = """You are verifying Bitcoin BIP 360 (Pay-to-Merkle-Root) script-path spends.

Rules, checked in this order (stop at the first failure):
1. bad_control_length: the control block c must have length 1 + 32*m for an integer m >= 0.
2. depth_exceeds_128: m must be at most 128.
3. bad_parity: the low bit of c[0] must be 1. The leaf version is v = c[0] & 0xfe.
4. root_mismatch: let k0 = tagged_hash("TapLeaf", v || compact_size(len(s)) || s), where
   s is the leaf script and compact_size is a single byte for lengths below 253.
   For j = 0..m-1, with e_j = c[1+32j : 33+32j]:
   k_{j+1} = tagged_hash("TapBranch", min(k_j, e_j) || max(k_j, e_j)) (byte-wise comparison).
   The spend fails if k_m != q.
If no rule fails, the spend is valid.

Use the tagged_hash tool for hashing. Finish with <answer>REASON</answer>, where REASON is one of:
valid, bad_control_length, depth_exceeds_128, bad_parity, root_mismatch."""


def expected_reason(q: bytes, script: bytes, control: bytes) -> str:
    """Ground truth, from the lab's validator, mapped to a reason code."""
    if len(control) < 1 or (len(control) - 1) % 32:
        return "bad_control_length"
    if (len(control) - 1) // 32 > MAX_MERKLE_DEPTH:
        return "depth_exceeds_128"
    if control[0] & 1 != 1:
        return "bad_parity"
    try:
        validate_script_path(q, script, control)
    except P2MRError:
        return "root_mismatch"
    return "valid"


def _random_tree(rng: random.Random, n_leaves: int):
    leaves = [{"script": rng.randbytes(rng.randint(1, 40)).hex()} for _ in range(n_leaves)]
    nodes = leaves
    while len(nodes) > 1:
        i = rng.randrange(len(nodes) - 1)
        nodes = nodes[:i] + [[nodes[i], nodes[i + 1]]] + nodes[i + 2:]
    return nodes[0]


def _mutate(rng: random.Random, q: bytes, script: bytes, control: bytes, kind: str):
    if kind == "valid":
        return q, script, control
    if kind == "bad_control_length":
        return q, script, control + rng.randbytes(rng.randint(1, 31))
    if kind == "depth_exceeds_128":
        return q, script, control + rng.randbytes(32) * (MAX_MERKLE_DEPTH + 1 - (len(control) - 1) // 32)
    if kind == "bad_parity":
        return q, script, bytes([control[0] & 0xFE]) + control[1:]
    # root_mismatch, via one of several realistic corruptions
    how = rng.choice(["pad_zero_element", "flip_path", "flip_script", "wrong_version", "wrong_q"])
    if how == "pad_zero_element":
        return q, script, control + bytes(32)
    if how == "flip_path" and len(control) > 1:
        i = rng.randrange(1, len(control))
        return q, script, control[:i] + bytes([control[i] ^ (1 << rng.randrange(8))]) + control[i + 1:]
    if how == "flip_script":
        i = rng.randrange(len(script))
        return q, script[:i] + bytes([script[i] ^ 0x01]) + script[i + 1:], control
    if how == "wrong_version":
        return q, script, bytes([0xC2 | 1]) + control[1:]
    return hashlib.sha256(q).digest(), script, control


def generate_tasks(n: int = 500, seed: int = 360, max_leaves: int = 6):
    rng = random.Random(seed)
    kinds = ["valid", "valid", "root_mismatch", "root_mismatch",
             "bad_control_length", "depth_exceeds_128", "bad_parity"]
    rows = []
    while len(rows) < n:
        tree = _random_tree(rng, rng.randint(1, max_leaves))
        out = construct_p2mr(tree)
        leaf_idx = rng.randrange(len(out["control_blocks"]))
        leaves = []

        def collect(node):
            if isinstance(node, dict):
                leaves.append(node)
            else:
                collect(node[0]); collect(node[1])
        collect(tree)
        q = out["merkle_root"]
        script = bytes.fromhex(leaves[leaf_idx]["script"])
        control = out["control_blocks"][leaf_idx]
        q, script, control = _mutate(rng, q, script, control, rng.choice(kinds))
        answer = expected_reason(q, script, control)
        rows.append({
            "question": (f"q (witness program): {q.hex()}\n"
                         f"s (leaf script): {script.hex()}\n"
                         f"c (control block, {len(control)} bytes): {control.hex()}"),
            "answer": answer,
            "info": {"m": (len(control) - 1) / 32},
        })
    return rows


def tagged_hash(tag: str, data_hex: str) -> str:
    """BIP 340 tagged hash: sha256(sha256(tag) || sha256(tag) || data).

    Args:
        tag: the tag string, e.g. "TapLeaf" or "TapBranch".
        data_hex: the message bytes as hex.

    Returns:
        The 32-byte hash as hex.
    """
    return _tagged_hash(tag, bytes.fromhex(data_hex)).hex()


def load_environment(num_train: int = 1000, num_eval: int = 200, max_leaves: int = 6, max_turns: int = 24, **kwargs):
    import verifiers as vf
    from datasets import Dataset

    parser = vf.XMLParser(["answer"], answer_field="answer")

    def correct_reason(completion, answer, **_):
        got = (parser.parse_answer(completion) or "").strip().lower()
        return 1.0 if got == answer else 0.0

    def correct_verdict(completion, answer, **_):
        got = (parser.parse_answer(completion) or "").strip().lower()
        if got not in REASONS:
            return 0.0
        return 1.0 if (got == "valid") == (answer == "valid") else 0.0

    rubric = vf.Rubric(funcs=[correct_reason, correct_verdict], weights=[0.7, 0.3], parser=parser)
    train = Dataset.from_list(generate_tasks(num_train, seed=360, max_leaves=max_leaves))
    test = Dataset.from_list(generate_tasks(num_eval, seed=2273, max_leaves=max_leaves))
    return vf.ToolEnv(
        dataset=train,
        eval_dataset=test,
        system_prompt=SYSTEM_PROMPT,
        parser=parser,
        rubric=rubric,
        tools=[tagged_hash],
        max_turns=max_turns,
        **kwargs,
    )
