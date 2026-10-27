#!/usr/bin/env python3
"""Concurrency stress test (not part of the unit suite; takes a few seconds).

N writer processes hammer one fresh temp memory tree at the same time:
each tries the same --id D times and appends U unique blocks. Expect exactly
one dup-id block, every unique block intact (no torn or interleaved writes),
and a clean `verify`. Usage: python3 tests/stress_concurrency.py [N] [U] [D]
"""
import multiprocessing as mp
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import memwrite  # noqa: E402

BODY = "Line one of a multi-line body.\nLine two: " + "x" * 400 + "\nLine three end."


def worker(args):
    root, w, uniq, dups = args
    root = Path(root)
    out = {"appended": 0, "skipped": 0}
    for i in range(max(uniq, dups)):
        if i < dups:
            r = memwrite.append_entry(root, "last-session.md", f"w{w}", "dup", "same task", task_id="dup-id")
            out[r["status"]] += 1
        if i < uniq:
            memwrite.append_entry(root, "decisions.md", f"w{w}", f"u-{w}-{i}", f"{BODY}\nmarker {w}-{i}")
    return out


def main():
    n, uniq, dups = (int(x) for x in (sys.argv[1:] + ["22", "50", "3"])[:3])
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "mem"
        memwrite.init_tree(root, "Test Owner", [f"w{i}" for i in range(n)], [])
        memwrite.anchor(root, "w0", "stress start")
        with mp.get_context("fork").Pool(n) as pool:
            res = pool.map(worker, [(str(root), w, uniq, dups) for w in range(n)])
        ls = (root / "last-session.md").read_text()
        dec = (root / "decisions.md").read_text()
        dup_blocks = ls.count("id: dup-id")
        blocks = re.findall(r"\n### [^\n]+ \| (u-\d+-\d+)\n<!-- by: w\d+ -->\n(.*?)\n(?=\n### |\Z)", dec, re.S)
        intact = sum(1 for name, body in blocks
                     if body == f"{BODY}\nmarker {name[2:]}")
        torn = uniq * n - intact
        rep = memwrite.verify(root)
        print(f"writers={n} unique_appends={uniq * n} dup_attempts={dups * n}")
        print(f"dup-id appended={sum(r['appended'] for r in res)} skipped={sum(r['skipped'] for r in res)} "
              f"blocks_in_file={dup_blocks} (want 1)")
        print(f"unique blocks intact={intact}/{uniq * n} torn_or_missing={torn}")
        print(f"verify ok={rep['ok']} errors={len(rep['errors'])} chained={rep['chained_records']}")
        ok = dup_blocks == 1 and torn == 0 and rep["ok"]
        print("PASS" if ok else "FAIL")
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
