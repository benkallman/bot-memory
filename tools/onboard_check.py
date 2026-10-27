#!/usr/bin/env python3
"""onboard_check: is a memory tree ready for agents to use?

Checks a memory root and exits 1 if any check fails:
  1. layout   - master/owner.md, registry.md, last-session.md, decisions.md exist
  2. template - no unreplaced {{PLACEHOLDER}} text and no TEMPLATE-ONLY lines
  3. secrets  - no secret-looking values or blocklisted phrases (same rules as memwrite)
  4. access   - files marked `access: private` are not group/other readable (POSIX)
  5. integrity - only with --verify: hash-chained log, diffs and file hashes
                 (same as `memwrite verify`). Off by default to keep the check cheap.
TODO markers are allowed (they are honest gaps) and are counted per file.
Use --strict to fail on TODOs too.

Usage: python3 tools/onboard_check.py [ROOT] [--strict] [--verify] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from memwrite import find_problems, LOG_DIR_NAME, verify  # noqa: E402

REQUIRED = ["master/owner.md", "registry.md", "last-session.md", "decisions.md"]
PLACEHOLDER_RE = re.compile(r"\{\{[^}]+\}\}")
TEMPLATE_LINE_RE = re.compile(r"TEMPLATE-ONLY")
TODO_RE = re.compile(r"\bTODO\b")
ACCESS_RE = re.compile(r"<!--\s*access:\s*(private|shared)\b", re.IGNORECASE)


def memory_files(root: Path):
    for path in sorted(root.rglob("*.md")):
        rel = path.relative_to(root)
        if rel.parts and rel.parts[0] in (LOG_DIR_NAME, ".git"):
            continue
        yield path


def check(root: Path, strict: bool = False, verify_chain: bool = False) -> dict:
    report = {"root": str(root), "errors": [], "todos": {}, "files": 0}
    for rel in REQUIRED:
        if not (root / rel).is_file():
            report["errors"].append(f"layout: missing {rel}")
    for path in memory_files(root):
        report["files"] += 1
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        for n, line in enumerate(text.splitlines(), 1):
            if PLACEHOLDER_RE.search(line):
                report["errors"].append(f"template: {rel}:{n} still has a {{{{placeholder}}}}")
            if TEMPLATE_LINE_RE.search(line):
                report["errors"].append(f"template: {rel}:{n} still has TEMPLATE-ONLY text")
        for name, n in find_problems(text, root):
            report["errors"].append(f"secrets: {rel}:{n} {name}")
        todos = len(TODO_RE.findall(text))
        if todos:
            report["todos"][rel] = todos
            if strict:
                report["errors"].append(f"strict: {rel} has {todos} TODO(s)")
        m = ACCESS_RE.search(text[:500])
        if m and m.group(1).lower() == "private" and os.name == "posix":
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                report["errors"].append(f"access: {rel} is marked private but mode is {oct(mode)} (want 0o600)")
    if verify_chain:
        rep = verify(root)
        report["errors"].extend(f"integrity: {e}" for e in rep["errors"])
        report["integrity_warnings"] = rep["warnings"]
        report["chain_head"] = rep["head"]
    report["ok"] = not report["errors"]
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=os.environ.get("MEMORY_ROOT", "."))
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--verify", action="store_true", help="also verify the hash-chained write log")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rep = check(Path(a.root).expanduser().resolve(), a.strict, a.verify)
    if a.json:
        print(json.dumps(rep, indent=2))
    else:
        for e in rep["errors"]:
            print("FAIL", e)
        for f, n in rep["todos"].items():
            print(f"TODO {f}: {n}")
        print(f"{'OK' if rep['ok'] else 'NOT READY'}: {rep['files']} file(s), "
              f"{len(rep['errors'])} error(s), {sum(rep['todos'].values())} TODO(s)")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
