"""Run the portable P2MR conformance pack against any implementation.

    python conformance/check.py --adapter "<command>"

The adapter is any program, in any language, that reads a JSON array of
{"id", "script_tree"} (or {"id", "spend"}) on stdin and writes a JSON array on stdout with, per case,
either {"id", "script_pubkey", "address", "control_blocks"} (hex strings, control
blocks in depth-first leaf order) or {"id", "error": "..."} when it rejects the
input; spend cases answer {"id", "valid": true}. See conformance/README.md. Exit status is 0 only if every case conforms.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--adapter", required=True, help="command that runs your adapter")
    ap.add_argument("--vectors", default=os.path.join(HERE, "vectors.json"))
    ap.add_argument("--group", action="append", help="only run these groups (repeatable)")
    ap.add_argument("--json", metavar="FILE", help="also write a machine-readable report")
    args = ap.parse_args()

    pack = json.load(open(args.vectors))
    cases = [c for c in pack["cases"] if not args.group or c["group"] in args.group]
    stdin = json.dumps([{"id": c["id"], "spend": c["spend"]} if "spend" in c
                        else {"id": c["id"], "script_tree": c["script_tree"]} for c in cases])
    cmd = args.adapter if os.name == "nt" else shlex.split(args.adapter)
    proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                          shell=os.name == "nt")
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        sys.exit(f"adapter exited with status {proc.returncode}")
    try:
        got = {r["id"]: r for r in json.loads(proc.stdout)}
    except (ValueError, KeyError, TypeError) as e:
        sys.exit(f"adapter output is not the expected JSON array: {e}")

    failures, by_group = [], {}
    for c in cases:
        g = by_group.setdefault(c["group"], [0, 0])
        g[1] += 1
        r, exp = got.get(c["id"]), c["expect"]
        if r is None:
            why = "no result returned"
        elif exp.get("reject"):
            why = None if "error" in r else "accepted an input the spec requires rejecting"
        elif exp.get("valid"):
            why = None if r.get("valid") is True else f"rejected a valid spend: {r.get('error')}"
        elif "error" in r:
            why = f"rejected a valid tree: {r['error']}"
        else:
            diffs = [k for k in ("script_pubkey", "address", "control_blocks")
                     if r.get(k) != exp[k]]
            why = ("mismatch in " + ", ".join(diffs)) if diffs else None
        if why:
            failures.append({"id": c["id"], "group": c["group"], "note": c["note"],
                             "reason": why})
        else:
            g[0] += 1

    for name, (ok, total) in by_group.items():
        print(f"{'PASS' if ok == total else 'FAIL'}  {name:9s} {ok}/{total}")
    for f in failures[:25]:
        print(f"  FAIL {f['id']}: {f['reason']}  ({f['note']})")
    if len(failures) > 25:
        print(f"  ... and {len(failures) - 25} more")
    passed = len(cases) - len(failures)
    print(f"\n{passed}/{len(cases)} P2MR conformance cases pass "
          f"(pack v{pack['version']}, bips @ {pack['upstream_bips_commit'][:12]})")
    print(pack["boundary"])
    if args.json:
        json.dump({"passed": passed, "total": len(cases), "failures": failures},
                  open(args.json, "w"), indent=1)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
