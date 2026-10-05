"""Reference adapter: this lab's own p2mr.py behind the conformance contract.

stdin : JSON array of {"id", "script_tree"}
stdout: JSON array of {"id", "script_pubkey", "address", "control_blocks"}
        or {"id", "error": "<message>"} when the implementation rejects the tree.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
import p2mr  # noqa: E402

out = []
for case in json.load(sys.stdin):
    try:
        r = p2mr.construct_p2mr(case["script_tree"])
        out.append({"id": case["id"],
                    "script_pubkey": r["script_pubkey"].hex(),
                    "address": r["address"],
                    "control_blocks": [c.hex() for c in r["control_blocks"]]})
    except p2mr.P2MRError as e:
        out.append({"id": case["id"], "error": str(e)})
json.dump(out, sys.stdout)
