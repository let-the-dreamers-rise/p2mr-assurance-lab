"""Shared pin enforcement: load upstream artifacts only if their SHA-256 matches
the manifest. Results against unpinned or altered artifacts are meaningless and
are never produced."""

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_manifest():
    with open(os.path.join(HERE, "vectors", "MANIFEST.json"), encoding="utf-8") as f:
        return json.load(f)


def load_pinned(local_path: str) -> bytes:
    """Return the raw bytes of a pinned artifact, hard-failing on hash mismatch."""
    manifest = load_manifest()
    entry = next((a for a in manifest["artifacts"] if a["local"] == local_path), None)
    if entry is None:
        print(f"FAIL: {local_path} is not a pinned artifact")
        sys.exit(1)
    with open(os.path.join(HERE, local_path), "rb") as f:
        raw = f.read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != entry["sha256"]:
        print(
            f"FAIL: {local_path} hash mismatch -- refusing to run against an unpinned artifact\n"
            f"  expected: {entry['sha256']}\n"
            f"  actual:   {digest}"
        )
        sys.exit(1)
    return raw


def load_pinned_json(local_path: str):
    return json.loads(load_pinned(local_path).decode("utf-8"))
