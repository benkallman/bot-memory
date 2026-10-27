#!/usr/bin/env python3
"""memwrite: append-only memory writer for agents.

Commands
  init    DIR  --owner NAME [--bot SLUG[=Display Name]]... [--project SLUG]...
          Create a fresh memory tree from the templates. Never overwrites.
  append  --file REL_PATH --agent NAME --heading TEXT [--text TEXT | stdin]
          [--root DIR] [--id TASK_ID] [--dry-run]
          Append one dated block to the end of an existing memory file.
          Refuses secrets and blocklisted phrases, never rewrites old text,
          logs a unified diff, and skips a repeated --id.
  scan    PATH...  (or stdin with -)
          Run the secret and blocklist checks on files or text. Exit 1 on hits.
  hash    PHRASE
          Print a blocklist line for PHRASE without storing the phrase itself.

The memory root comes from --root, else $MEMORY_ROOT, else the current dir.
Standard library only. Python 3.8+.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import difflib
import hashlib
import json
import os
import re
import sys
from pathlib import Path

try:
    import fcntl  # POSIX only
except ImportError:  # pragma: no cover - Windows
    fcntl = None

REPO_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = REPO_DIR / "templates"
LOG_DIR_NAME = "logs"
BLOCKLIST_NAME = ".blocklist"

# --------------------------------------------------------------------------
# Secret detection. Each rule: (name, compiled regex). Matches are never
# printed in full; only the rule name and line number are reported.
# --------------------------------------------------------------------------
_I = re.IGNORECASE

SECRET_RULES = [
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("openai-style-key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}")),
    ("stripe-key", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("bearer-token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("url-credentials", re.compile(r"[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@", _I)),
    # password = x / password: x / password is x  (any non-empty value)
    ("password-value", re.compile(
        r"\b(?:password|passwd|pwd|passphrase|passcode)\b\s*(?:is|was|=|:|->)\s*[\"'`]?(?!\s|\*{3,}|<|\{\{|TODO)\S{3,}", _I)),
    # token/secret/api key = long opaque value
    ("credential-value", re.compile(
        r"\b(?:api[ _-]?key|apikey|secret(?:[ _-]?key)?|client[ _-]?secret|access[ _-]?token|auth[ _-]?token|"
        r"refresh[ _-]?token|session[ _-]?(?:token|cookie)|private[ _-]?key|token)\b\s*(?:is|=|:)\s*[\"'`]?"
        r"(?=[A-Za-z0-9_\-+/=.]{16,})(?=\S*\d)(?=\S*[A-Za-z])[A-Za-z0-9_\-+/=.]{16,}", _I)),
    # One-time / verification / pairing codes: keyword then a short code.
    ("otp-like-code", re.compile(
        r"\b(?:otp|2fa|mfa|totp|one[- ]time(?: pass(?:word|code))?|verification|passcode|pin|code)\b"
        r"(?:\s+(?:code|pin|number))?\s*(?:is|was|=|:|of|->)?\s*[\"'`]?"
        r"(?:\d{4,8}(?![-/.:,]\d)\b|(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{3,5}-[A-Z0-9]{3,5}\b|\d{3}[ -]\d{3}(?![-/.:]\d)\b)", _I)),
    ("ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("ssn-keyword", re.compile(r"\b(?:ssn|social security(?: number| no\.?)?)\b\D{0,15}\d{4,9}", _I)),
]

_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _normalize_words(text: str):
    return re.findall(r"[a-z0-9']+", text.lower())


def phrase_hash(phrase: str) -> str:
    norm = " ".join(_normalize_words(phrase))
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def load_blocklist(root: Path | None):
    """Return (plain_phrases, hashed) from ROOT/.blocklist.

    Lines: '# comment', a plain phrase, or 'sha256:<hex>' (see `hash`).
    Hashed entries let you block a phrase without writing it down anywhere.
    """
    plain, hashed = [], set()
    if root is None:
        return plain, hashed
    path = Path(root) / BLOCKLIST_NAME
    if not path.is_file():
        return plain, hashed
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("sha256:"):
            hashed.add(line.split(":", 1)[1].strip().lower())
        else:
            plain.append(line)
    return plain, hashed


def find_problems(text: str, root: Path | None = None):
    """Return a list of (rule, line_number) for secrets or blocked phrases."""
    problems = []
    plain, hashed = load_blocklist(root)
    for lineno, line in enumerate(text.splitlines(), 1):
        for name, rx in SECRET_RULES:
            if rx.search(line):
                problems.append((name, lineno))
        for m in _CARD_RE.finditer(line):
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19 and _luhn_ok(digits) and len(set(digits)) > 1:
                problems.append(("payment-card-number", lineno))
        for phrase in plain:
            words = _normalize_words(phrase)
            if words and re.search(r"(?<![a-z0-9'])" + r"[^a-z0-9']+".join(map(re.escape, words)) + r"(?![a-z0-9'])", line.lower()):
                problems.append(("blocklisted-phrase", lineno))
        if hashed:
            words = _normalize_words(line)
            hit = False
            for n in range(1, 7):
                for i in range(0, max(0, len(words) - n + 1)):
                    h = hashlib.sha256(" ".join(words[i:i + n]).encode("utf-8")).hexdigest()
                    if h in hashed:
                        hit = True
                        break
                if hit:
                    break
            if hit:
                problems.append(("blocklisted-phrase", lineno))
    return problems


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _now():
    return _dt.datetime.now().astimezone()


def _stamp(now=None):
    now = now or _now()
    return now.strftime("%Y-%m-%d %H:%M %z")


def resolve_root(arg: str | None) -> Path:
    root = arg or os.environ.get("MEMORY_ROOT") or os.getcwd()
    return Path(root).expanduser().resolve()


def resolve_target(root: Path, rel: str) -> Path:
    target = (root / rel).resolve() if not os.path.isabs(rel) else Path(rel).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise SystemExit(f"refused: {rel} is outside the memory root {root}")
    if target.suffix.lower() != ".md":
        raise SystemExit("refused: only .md memory files can be written")
    if LOG_DIR_NAME in target.relative_to(root).parts[:1]:
        raise SystemExit("refused: logs/ is written by the tool only")
    return target


def _private_mkdir(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def _write_private(path: Path, text: str, mode="w"):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | (os.O_APPEND if mode == "a" else os.O_TRUNC), 0o600)
    with os.fdopen(fd, mode, encoding="utf-8") as fh:
        fh.write(text)


def _already_applied(log_path: Path, task_id: str, rel: str) -> bool:
    if not task_id or not log_path.is_file():
        return False
    for line in log_path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("id") == task_id and rec.get("file") == rel:
            return True
    return False


def build_block(heading: str, agent: str, text: str, task_id: str | None, now=None) -> str:
    heading = " ".join(heading.split())
    meta = f"by: {agent}" + (f"; id: {task_id}" if task_id else "")
    body = text.strip("\n")
    return f"\n### {_stamp(now)} | {heading}\n<!-- {meta} -->\n{body}\n"


def append_entry(root: Path, rel: str, agent: str, heading: str, text: str,
                 task_id: str | None = None, dry_run: bool = False, now=None) -> dict:
    """Append a block. Returns a result dict. Raises SystemExit on refusal."""
    if not agent or not heading:
        raise SystemExit("refused: --agent and --heading are required")
    if not text.strip():
        raise SystemExit("refused: empty text")
    target = resolve_target(root, rel)
    if not target.is_file():
        raise SystemExit(f"refused: {rel} does not exist (create it with `init` or from a template first)")
    rel_norm = target.relative_to(root).as_posix()

    probs = find_problems("\n".join([heading, agent, task_id or "", text]), root)
    if probs:
        detail = ", ".join(sorted({f"{n} (line {l})" for n, l in probs}))
        raise SystemExit(f"refused: possible secret or blocked phrase: {detail}. Nothing was written.")

    log_dir = root / LOG_DIR_NAME
    writes_log = log_dir / "writes.jsonl"
    if _already_applied(writes_log, task_id, rel_norm):
        return {"status": "skipped", "reason": "id already applied", "file": rel_norm}

    block = build_block(heading, agent, text, task_id, now)
    if dry_run:
        return {"status": "dry-run", "file": rel_norm, "block": block}

    with open(target, "a+", encoding="utf-8") as fh:
        if fcntl:
            fcntl.flock(fh, fcntl.LOCK_EX)
        fh.seek(0)
        before = fh.read()
        prefix = "" if before.endswith("\n") or not before else "\n"
        fh.write(prefix + block)
        fh.flush()
        os.fsync(fh.fileno())
        fh.seek(0)
        after = fh.read()
        if fcntl:
            fcntl.flock(fh, fcntl.LOCK_UN)
    if not after.startswith(before):  # should be impossible with O_APPEND
        raise SystemExit("error: append-only check failed; inspect the file")

    now = now or _now()
    _private_mkdir(log_dir)
    _private_mkdir(log_dir / "diffs")
    diff = "".join(difflib.unified_diff(
        before.splitlines(True), after.splitlines(True),
        fromfile=f"a/{rel_norm}", tofile=f"b/{rel_norm}"))
    diff_name = now.strftime("%Y%m%d-%H%M%S-%f") + "-" + re.sub(r"[^A-Za-z0-9._-]+", "_", rel_norm) + ".diff"
    _write_private(log_dir / "diffs" / diff_name, diff)
    rec = {
        "time": now.isoformat(timespec="seconds"), "agent": agent, "file": rel_norm,
        "id": task_id, "heading": " ".join(heading.split()),
        "sha256_before": hashlib.sha256(before.encode()).hexdigest(),
        "sha256_after": hashlib.sha256(after.encode()).hexdigest(),
        "bytes_added": len(after.encode()) - len(before.encode()),
        "diff": f"{LOG_DIR_NAME}/diffs/{diff_name}",
    }
    _write_private(writes_log, json.dumps(rec) + "\n", mode="a")
    return {"status": "appended", **rec}


# --------------------------------------------------------------------------
# init
# --------------------------------------------------------------------------

def _slugify(name: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", name.lower())).strip("-") or "item"


def _render(template: str, values: dict) -> str:
    for key, val in values.items():
        template = template.replace("{{" + key + "}}", val)
    return template


def init_tree(dest: Path, owner: str, bots, projects, now=None) -> list:
    """Create a memory tree. Returns created paths. Never overwrites."""
    now = now or _now()
    created = []
    date = now.strftime("%Y-%m-%d")
    base = {"OWNER": owner, "DATE": date}

    def make(rel: str, tpl: str, extra=None):
        path = dest / rel
        if path.exists():
            return
        _private_mkdir(path.parent)
        text = _render((TEMPLATE_DIR / tpl).read_text(encoding="utf-8"), {**base, **(extra or {})})
        _write_private(path, text)
        created.append(path)

    _private_mkdir(dest)
    make("master/owner.md", "master/owner.md")
    make("master/rules.md", "master/rules.md")
    make("registry.md", "registry.md")
    make("last-session.md", "last-session.md")
    make("decisions.md", "decisions.md")
    for spec in bots:
        slug, _, display = spec.partition("=")
        display = display or slug
        make(f"bots/{_slugify(slug)}.md", "bot.md", {"BOT_NAME": display, "BOT_SLUG": _slugify(slug)})
    for spec in projects:
        slug, _, display = spec.partition("=")
        display = display or slug
        make(f"projects/{_slugify(slug)}.md", "project.md", {"PROJECT_NAME": display, "PROJECT_SLUG": _slugify(slug)})
    return created


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="memwrite", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="create a memory tree from templates")
    pi.add_argument("dest")
    pi.add_argument("--owner", required=True)
    pi.add_argument("--bot", action="append", default=[], help="slug or slug=Display Name")
    pi.add_argument("--project", action="append", default=[], help="slug or slug=Display Name")

    pa = sub.add_parser("append", help="append a dated block to a memory file")
    pa.add_argument("--root")
    pa.add_argument("--file", required=True)
    pa.add_argument("--agent", required=True)
    pa.add_argument("--heading", required=True)
    pa.add_argument("--text", help="block text; read from stdin if omitted")
    pa.add_argument("--id", dest="task_id")
    pa.add_argument("--dry-run", action="store_true")

    ps = sub.add_parser("scan", help="check files or stdin for secrets")
    ps.add_argument("paths", nargs="+")
    ps.add_argument("--root", help="memory root whose .blocklist to apply")

    ph = sub.add_parser("hash", help="print a hashed blocklist line")
    ph.add_argument("phrase")

    args = p.parse_args(argv)

    if args.cmd == "init":
        created = init_tree(Path(args.dest).expanduser().resolve(), args.owner, args.bot, args.project)
        for c in created:
            print(f"created {c}")
        print(f"{len(created)} file(s) created. Next: replace every {{{{...}}}} and run tools/onboard_check.py")
        return 0

    if args.cmd == "append":
        root = resolve_root(args.root)
        text = args.text if args.text is not None else sys.stdin.read()
        res = append_entry(root, args.file, args.agent, args.heading, text, args.task_id, args.dry_run)
        if res["status"] == "dry-run":
            print(res["block"])
        else:
            print(json.dumps(res))
        return 0

    if args.cmd == "scan":
        root = Path(args.root).expanduser().resolve() if args.root else None
        bad = 0
        for item in args.paths:
            if item == "-":
                text, label = sys.stdin.read(), "<stdin>"
            else:
                text, label = Path(item).read_text(encoding="utf-8", errors="replace"), item
            for name, line in find_problems(text, root):
                print(f"{label}:{line}: {name}")
                bad += 1
        print(f"{bad} problem(s) found")
        return 1 if bad else 0

    if args.cmd == "hash":
        print(f"sha256:{phrase_hash(args.phrase)}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
