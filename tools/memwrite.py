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
  approve --file REL --agent APPROVER --heading TEXT [--text TEXT | stdin]
          One-time owner approval (24 h) for one exact append to an owner-only
          file (master/* by default). Prints a token for append --owner-approval.
  verify  [--root DIR] [--expect-head HASH]
          Check the hash-chained log, diff files and current file hashes.
  anchor  --agent NAME [--note TEXT]
          Record every memory file's sha256 into the chain (once, at install).

Write ACLs live in ROOT/.acl.json (see docs/integrity.md). All writes hold
ROOT/logs/.write.lock, so --id dedupe and the log chain are race-free.

The memory root comes from --root, else $MEMORY_ROOT, else the current dir.
Standard library only. Python 3.8+.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import difflib
import fnmatch
import hashlib
import hmac
import json
import os
import re
import secrets
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

_OTP_KW = (r"(?:otp|2fa|mfa|totp|one[- ]time(?:[- ]pass(?:word|code)?|[- ]code)?|verification|verify|passcode|"
           r"security[- ]code|auth(?:entication)?[- ]code|log[- ]?in[- ]code|sign[- ]?in[- ]code|pairing[- ]code|pin|code)")
_OTP_STRONG_KW = r"(?:otp|2fa|mfa|totp|one[- ]time[- ]?(?:pass(?:word|code)?|code)|verification[- ]code|passcode|pin)"
_NOT_A_DATE8 = r"(?!(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?!\d))"
_PW_KW = r"(?:password|passwd|pwd|passphrase|passcode|pw|pass)"
_PW_FOR = r"(?:\s+(?:for|to|on|of)\s+(?:the\s+|my\s+|his\s+|her\s+)?[\w.@+-]{1,40}(?:\s+account)?)?"
_PLACEHOLDER = r"(?!\s|\*{3,}|<|\{\{|TODO|\[redacted|\(redacted|redacted\b|in\s+the\s+vault|vault\b|n/?a\b|none\b|unknown\b)"

SECRET_RULES = [
    # Key material
    ("private-key-block", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("putty-private-key", re.compile(r"PuTTY-User-Key-File-\d")),
    ("recovery-key-888k1", re.compile(r"\b888k1[-_:.]?[A-Za-z0-9_+/=-]{16,}", _I)),
    # Provider token formats
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("openai-style-key", re.compile(r"\bsk-(?:proj-|ant-(?:api|admin)\d{0,2}-|ant-|svcacct-|admin-|or-v1-)?[A-Za-z0-9_-]{20,}")),
    ("xai-key", re.compile(r"\bxai-[A-Za-z0-9_-]{20,}")),
    ("slack-token", re.compile(r"\bxox[abposre]-[A-Za-z0-9-]{10,}|\bxapp-\d-[A-Za-z0-9-]{10,}")),
    ("slack-webhook", re.compile(r"hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,}")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("aws-secret-key", re.compile(r"aws_?secret_?(?:access_?)?key\W{0,6}[A-Za-z0-9/+=]{40}", _I)),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("google-oauth", re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}|\bGOCSPX-[A-Za-z0-9_-]{20,}")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}")),
    ("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}")),
    ("stripe-key", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("bearer-token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("url-credentials", re.compile(r"[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@", _I)),
    # password = x / pw for gmail: x / password is x  (any non-placeholder value)
    ("password-value", re.compile(
        r"\b(?:password|passwd|pwd|passphrase|passcode|pw)\b" + _PW_FOR +
        r"\s*(?:is|was|=|:|->)\s*[\"'`]?" + _PLACEHOLDER + r"\S{3,}", _I)),
    # "pass: x" is common English ("tests pass: 31/31"), so require a mixed value
    ("password-value", re.compile(
        r"\bpass\b" + _PW_FOR + r"\s*(?:=|:|->)\s*[\"'`]?" + _PLACEHOLDER +
        r"(?=\S*[A-Za-z])(?=\S*\d)\S{6,}", _I)),
    # no separator: password word, a space, then a mixed letters+digits value of 8+
    ("password-value", re.compile(
        r"\b(?:password|passwd|pwd|passphrase|pw)\b\s+[\"'`]?(?=\S*[A-Za-z])(?=\S*\d)[^\s\"'`]{8,}", _I)),
    # token/secret/api key = long opaque value
    ("credential-value", re.compile(
        r"\b(?:api[ _-]?key|apikey|secret(?:[ _-]?key)?|client[ _-]?secret|access[ _-]?token|auth[ _-]?token|"
        r"refresh[ _-]?token|session[ _-]?(?:token|cookie)|private[ _-]?key|token)\b\s*(?:is|=|:)\s*[\"'`]?"
        r"(?=[A-Za-z0-9_\-+/=.]{16,})(?=\S*\d)(?=\S*[A-Za-z])[A-Za-z0-9_\-+/=.]{16,}", _I)),
    ("credential-value", re.compile(
        r"\bkey\b\s*(?:=|:)\s*[\"'`]?(?=\S*\d)(?=\S*[A-Za-z])[A-Za-z0-9_\-+/=.]{24,}", _I)),
    # One-time / verification codes. 6-8 digits (or 123 456) within a few
    # words after a code keyword. 4-5 digits only with a strong keyword and an
    # explicit "is", ":" or "=" after the word, so "PIN 1234 is the gate number" and
    # "Code 2026 release plan" pass.
    ("otp-like-code", re.compile(
        r"\b" + _OTP_KW + r"s?\b[^\d\n]{0,25}?(?<![A-Za-z0-9#./:$-])" + _NOT_A_DATE8 +
        r"(?:\d{6,8}|\d{3}[ -]\d{3})(?![-/.:,]?\d)(?![A-Za-z])", _I)),
    ("otp-like-code", re.compile(
        r"\b" + _OTP_STRONG_KW + r"\b(?:\s+(?:code|number))?\s*(?:is|was|=|:|->)\s*[\"'`]?\d{4,5}(?![-/.:,]?\d)\b", _I)),
    ("otp-like-code", re.compile(
        r"\b(?i:" + _OTP_KW + r")s?\b[^\n]{0,25}?\b(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{3,5}-[A-Z0-9]{3,5}\b")),
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


# --------------------------------------------------------------------------
# Write lock. One lock file per memory root serialises every write: the --id
# dedupe check, the file append, the diff and the log record all happen while
# it is held, so the log is one linear history.
# --------------------------------------------------------------------------

LOCK_NAME = ".write.lock"
WRITES_LOG = "writes.jsonl"
APPROVAL_DIR = "approvals"
ACL_NAME = ".acl.json"
DEFAULT_OWNER_ONLY = ["master/*"]
RESERVED_AGENTS = {"owner", "ben", "ben-kallman", "system", "memwrite", "root"}
APPROVAL_TTL_HOURS = 24


class _RootLock:
    def __init__(self, root: Path):
        self.log_dir = root / LOG_DIR_NAME
        self.fh = None

    def __enter__(self):
        _private_mkdir(self.log_dir)
        fd = os.open(self.log_dir / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
        self.fh = os.fdopen(fd, "r+")
        if fcntl:
            fcntl.flock(self.fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        if fcntl:
            fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()
        return False


def _already_applied(log_path: Path, task_id: str, rel: str) -> bool:
    """Call only while holding _RootLock."""
    if not task_id or not log_path.is_file():
        return False
    needle = json.dumps(task_id)
    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            if needle not in line:  # cheap pre-filter
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("id") == task_id and rec.get("file") == rel and rec.get("type", "write") == "write":
                return True
    return False


# --------------------------------------------------------------------------
# Hash chain. Every new log record carries seq, prev (entry hash of the record
# before it) and entry = sha256 of its own canonical JSON. The first chained
# record (genesis) sets prev = sha256 of all older, unchained log bytes, which
# pins those legacy lines too. Optional HMAC: set MEMWRITE_HMAC_KEY_FILE.
# A key readable by the same OS user as every bot only stops tools that do
# not know about the key; see docs/integrity.md.
# --------------------------------------------------------------------------

def _canon(rec: dict) -> bytes:
    body = {k: v for k, v in rec.items() if k not in ("entry", "mac")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hmac_key():
    path = os.environ.get("MEMWRITE_HMAC_KEY_FILE")
    if not path:
        return None
    try:
        key = Path(path).expanduser().read_bytes().strip()
    except OSError:
        raise SystemExit("refused: MEMWRITE_HMAC_KEY_FILE is set but unreadable")
    return key or None


def _last_line(path: Path) -> bytes:
    if not path.is_file():
        return b""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        end = fh.tell()
        if end == 0:
            return b""
        pos, chunk, buf = end, 4096, b""
        while pos > 0:
            step = min(chunk, pos)
            pos -= step
            fh.seek(pos)
            buf = fh.read(step) + buf
            stripped = buf.rstrip(b"\n")
            if b"\n" in stripped:
                return stripped.rsplit(b"\n", 1)[1]
        return buf.rstrip(b"\n")


def _sha_file_bytes(path: Path) -> str:
    h = hashlib.sha256()
    if path.is_file():
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 16), b""):
                h.update(block)
    return h.hexdigest()


def _chain_append(log_path: Path, rec: dict) -> dict:
    """Append rec as the next chained record. Call only under _RootLock."""
    last = _last_line(log_path)
    prev_rec = None
    if last:
        try:
            prev_rec = json.loads(last)
        except ValueError:
            prev_rec = None
    if prev_rec and prev_rec.get("entry"):
        rec = {**rec, "v": 2, "seq": int(prev_rec.get("seq", 0)) + 1, "prev": prev_rec["entry"]}
    else:
        rec = {**rec, "v": 2, "seq": 1, "genesis": True, "prev": _sha_file_bytes(log_path)}
    rec["entry"] = hashlib.sha256(_canon(rec)).hexdigest()
    key = _hmac_key()
    if key:
        rec["mac"] = hmac.new(key, rec["entry"].encode(), hashlib.sha256).hexdigest()
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return rec


# --------------------------------------------------------------------------
# Write ACLs (ROOT/.acl.json). Identity is the --agent string, so this stops
# mistakes and instruction-following bots, not a hostile process running as
# the same OS user. See docs/integrity.md.
# --------------------------------------------------------------------------

AGENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()'&+-]{0,63}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$")
META_COMMENT_RE = re.compile(r"<!--\s*(?:by|id|access|owner|owner[- ]approved|approved)\s*:", _I)
FAKE_HEADER_RE = re.compile(r"^\s{0,3}#{1,6}\s+\d{4}-\d{2}-\d{2}\s+\d{1,2}:\d{2}", re.M)


def agent_slug(agent: str) -> str:
    """'Helper Bot (executor)' -> 'helper-bot'."""
    base = re.sub(r"\s*\([^)]*\)\s*$", "", agent.strip())
    return _slugify(base)


def load_acl(root: Path):
    path = Path(root) / ACL_NAME
    if not path.is_file():
        return None
    try:
        acl = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SystemExit(f"refused: {ACL_NAME} is not valid JSON ({exc.__class__.__name__}); fix it before writing")
    if not isinstance(acl, dict) or not isinstance(acl.get("agents", {}), dict):
        raise SystemExit(f"refused: {ACL_NAME} must be an object with an 'agents' object")
    return acl


def resolve_agent(acl, agent: str):
    s = agent_slug(agent)
    if acl is None:
        return s
    for slug, cfg in acl.get("agents", {}).items():
        names = [slug] + list((cfg or {}).get("aliases", []))
        if s in {agent_slug(n) for n in names}:
            return slug
    return None


def _match(rel: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(rel, p) for p in patterns or [])


def owner_only_patterns(acl):
    return (acl or {}).get("owner_only", DEFAULT_OWNER_ONLY)


def allowed_files(acl, slug: str):
    cfg = (acl or {}).get("agents", {}).get(slug) or {}
    allow = [f"bots/{slug}.md"] if cfg.get("own_file", True) else []
    if cfg.get("shared", True):
        allow += list(acl.get("shared_writable", []))
    return allow + list(cfg.get("write", []))


def check_identity_and_text(agent: str, heading: str, text: str, task_id):
    if not AGENT_RE.match(agent):
        raise SystemExit("refused: --agent must be 1-64 letters, digits, spaces or ._()'&+- (no markup)")
    if agent_slug(agent) in RESERVED_AGENTS:
        raise SystemExit(f"refused: agent name '{agent_slug(agent)}' is reserved; owner text goes in via an owner approval")
    if task_id is not None and not ID_RE.match(task_id):
        raise SystemExit("refused: --id must be 1-128 letters, digits or ._:@/+- (no spaces or markup)")
    if "<!--" in heading or "-->" in heading:
        raise SystemExit("refused: --heading may not contain HTML comment markers")
    if META_COMMENT_RE.search(text):
        raise SystemExit("refused: text contains a '<!-- by:/id:/access:/owner: -->' style marker; "
                         "only the tool writes block metadata (forged attribution)")
    if FAKE_HEADER_RE.search(text):
        raise SystemExit("refused: text contains a line that looks like a dated block heading (### YYYY-MM-DD HH:MM); "
                         "only the tool writes block headings")


def check_write_allowed(acl, rel: str, agent: str) -> dict:
    """Return {'slug', 'owner_only'} or raise SystemExit."""
    owner_only = _match(rel, owner_only_patterns(acl))
    slug = resolve_agent(acl, agent)
    if acl is None:
        return {"slug": slug, "owner_only": owner_only}
    if slug is None:
        known = ", ".join(sorted(acl.get("agents", {})))
        raise SystemExit(f"refused: agent '{agent}' is not in {ACL_NAME}. Use your bot name or slug from registry.md "
                         f"(known: {known}).")
    if owner_only:
        return {"slug": slug, "owner_only": True}
    if not _match(rel, allowed_files(acl, slug)):
        raise SystemExit(f"refused: '{slug}' may not write {rel} (see {ACL_NAME}). Allowed: "
                         + ", ".join(allowed_files(acl, slug)))
    return {"slug": slug, "owner_only": False}


def _approval_digest(rel: str, heading: str, text: str) -> str:
    norm = json.dumps([rel, " ".join(heading.split()), text.strip("\n")], ensure_ascii=False)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def create_approval(root: Path, rel: str, agent: str, heading: str, text: str, now=None,
                    ttl_hours: float = APPROVAL_TTL_HOURS) -> dict:
    """Owner-approval marker for one exact append to an owner-only file."""
    if not agent or not heading or not text.strip():
        raise SystemExit("refused: --agent, --heading and text are required")
    check_identity_and_text(agent, heading, text, None)
    target = resolve_target(root, rel)
    rel_norm = target.relative_to(root).as_posix()
    acl = load_acl(root)
    if acl is None:
        raise SystemExit(f"refused: owner approvals need {ACL_NAME} with an 'approvers' list")
    slug = resolve_agent(acl, agent)
    if slug is None or slug not in acl.get("approvers", []):
        raise SystemExit(f"refused: '{agent}' is not an approver in {ACL_NAME}")
    if not _match(rel_norm, owner_only_patterns(acl)):
        raise SystemExit(f"refused: {rel_norm} is not owner-only; append to it normally")
    probs = find_problems("\n".join([heading, text]), root)
    if probs:
        raise SystemExit("refused: possible secret or blocked phrase in approved text. Nothing was written.")
    now = now or _now()
    token = "appr-" + secrets.token_hex(8)
    rec = {"token": token, "file": rel_norm, "approver": slug, "digest": _approval_digest(rel_norm, heading, text),
           "created": now.isoformat(timespec="seconds"),
           "expires": (now + _dt.timedelta(hours=ttl_hours)).isoformat(timespec="seconds")}
    with _RootLock(root):
        adir = root / LOG_DIR_NAME / APPROVAL_DIR
        _private_mkdir(adir)
        _write_private(adir / f"{token}.json", json.dumps(rec) + "\n")
        _chain_append(root / LOG_DIR_NAME / WRITES_LOG, {
            "type": "approval", "time": rec["created"], "agent": agent, "file": rel_norm,
            "approval": token, "digest": rec["digest"], "expires": rec["expires"]})
    return rec


def _check_approval(root: Path, token: str, rel: str, heading: str, text: str, now) -> Path:
    if not token or not re.fullmatch(r"appr-[0-9a-f]{16}", token):
        raise SystemExit(f"refused: {rel} is owner-only. Brain must run `memwrite approve` for this exact text, "
                         "then append with --owner-approval TOKEN")
    path = root / LOG_DIR_NAME / APPROVAL_DIR / f"{token}.json"
    if not path.is_file():
        raise SystemExit("refused: owner approval not found or already used")
    rec = json.loads(path.read_text(encoding="utf-8"))
    if rec.get("file") != rel:
        raise SystemExit("refused: owner approval is for a different file")
    if rec.get("digest") != _approval_digest(rel, heading, text):
        raise SystemExit("refused: text or heading differs from what was approved")
    if _dt.datetime.fromisoformat(rec["expires"]) < now:
        raise SystemExit("refused: owner approval expired")
    return path


# --------------------------------------------------------------------------
# append
# --------------------------------------------------------------------------

def build_block(heading: str, agent: str, text: str, task_id: str | None, now=None, approval=None) -> str:
    heading = " ".join(heading.split())
    meta = f"by: {agent}" + (f"; id: {task_id}" if task_id else "") + (f"; owner-approved: {approval}" if approval else "")
    body = text.strip("\n")
    return f"\n### {_stamp(now)} | {heading}\n<!-- {meta} -->\n{body}\n"


def append_entry(root: Path, rel: str, agent: str, heading: str, text: str,
                 task_id: str | None = None, dry_run: bool = False, now=None,
                 owner_approval: str | None = None) -> dict:
    """Append a block. Returns a result dict. Raises SystemExit on refusal."""
    if not agent or not heading:
        raise SystemExit("refused: --agent and --heading are required")
    if not text.strip():
        raise SystemExit("refused: empty text")
    check_identity_and_text(agent, heading, text, task_id)
    target = resolve_target(root, rel)
    if not target.is_file():
        raise SystemExit(f"refused: {rel} does not exist (create it with `init` or from a template first)")
    rel_norm = target.relative_to(root).as_posix()
    acl = load_acl(root)
    perm = check_write_allowed(acl, rel_norm, agent)

    probs = find_problems("\n".join([heading, agent, task_id or "", text]), root)
    if probs:
        detail = ", ".join(sorted({f"{n} (line {l})" for n, l in probs}))
        raise SystemExit(f"refused: possible secret or blocked phrase: {detail}. Nothing was written.")

    now = now or _now()
    if perm["owner_only"]:
        _check_approval(root, owner_approval, rel_norm, heading, text, now)
    block = build_block(heading, agent, text, task_id, now, owner_approval if perm["owner_only"] else None)
    if dry_run:
        return {"status": "dry-run", "file": rel_norm, "block": block}

    log_dir = root / LOG_DIR_NAME
    writes_log = log_dir / WRITES_LOG
    with _RootLock(root):
        if _already_applied(writes_log, task_id, rel_norm):
            return {"status": "skipped", "reason": "id already applied", "file": rel_norm}
        approval_path = None
        if perm["owner_only"]:  # re-check under the lock so a token is used once
            approval_path = _check_approval(root, owner_approval, rel_norm, heading, text, now)
        with open(target, "a+", encoding="utf-8") as fh:
            if fcntl:  # also lock the file itself, for older writers that lock only the file
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
        if approval_path is not None:
            os.replace(approval_path, approval_path.with_suffix(".used"))

        _private_mkdir(log_dir / "diffs")
        diff = "".join(difflib.unified_diff(
            before.splitlines(True), after.splitlines(True),
            fromfile=f"a/{rel_norm}", tofile=f"b/{rel_norm}"))
        diff_name = now.strftime("%Y%m%d-%H%M%S-%f") + "-" + secrets.token_hex(3) + "-" + \
            re.sub(r"[^A-Za-z0-9._-]+", "_", rel_norm) + ".diff"
        _write_private(log_dir / "diffs" / diff_name, diff)
        added = after[len(before):]
        rec = {
            "type": "write",
            "time": now.isoformat(timespec="seconds"), "agent": agent, "file": rel_norm,
            "id": task_id, "heading": " ".join(heading.split()),
            "sha256_before": hashlib.sha256(before.encode()).hexdigest(),
            "sha256_after": hashlib.sha256(after.encode()).hexdigest(),
            "content_sha256": hashlib.sha256(added.encode()).hexdigest(),
            "bytes_added": len(after.encode()) - len(before.encode()),
            "diff": f"{LOG_DIR_NAME}/diffs/{diff_name}",
            "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
        }
        if perm["owner_only"]:
            rec["approval"] = owner_approval
        rec = _chain_append(writes_log, rec)
    return {"status": "appended", **rec}


# --------------------------------------------------------------------------
# verify / anchor
# --------------------------------------------------------------------------

def _memory_md_files(root: Path):
    for path in sorted(root.rglob("*.md")):
        rel = path.relative_to(root)
        if rel.parts and rel.parts[0] in (LOG_DIR_NAME, ".git"):
            continue
        yield rel.as_posix(), path


def verify(root: Path, expect_head: str | None = None, check_files: bool = True) -> dict:
    """Check the log chain, diffs and current file hashes. Prints no content."""
    errors, warnings = [], []
    log_path = root / LOG_DIR_NAME / WRITES_LOG
    key = _hmac_key()
    known = {}          # rel -> last known sha256
    started = False
    prev_entry, prev_seq, head, entries = None, 0, None, set()
    legacy = chained = 0
    offset = 0
    raw = log_path.read_bytes() if log_path.is_file() else b""
    lines = raw.split(b"\n")
    for i, line in enumerate(lines, 1):
        start = offset
        offset += len(line) + 1
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            errors.append(f"log line {i}: not valid JSON (edited or torn)")
            continue
        if "entry" not in rec:
            legacy += 1
            if started:
                errors.append(f"log line {i}: unchained record after the chain started (old tool or inserted line)")
            rel = rec.get("file")
            if rel and rec.get("sha256_after"):
                if rel in known and rec.get("sha256_before") != known[rel]:
                    warnings.append(f"log line {i}: legacy record for {rel} does not follow the previous one")
                known[rel] = rec["sha256_after"]
            continue
        chained += 1
        if hashlib.sha256(_canon(rec)).hexdigest() != rec["entry"]:
            errors.append(f"log line {i}: entry hash mismatch (record edited)")
        if key:
            want = hmac.new(key, str(rec.get("entry")).encode(), hashlib.sha256).hexdigest()
            if rec.get("mac") != want:
                errors.append(f"log line {i}: missing or bad HMAC")
        if rec.get("genesis"):
            if started:
                errors.append(f"log line {i}: second genesis record (chain was cut and restarted)")
            if rec.get("prev") != hashlib.sha256(raw[:start]).hexdigest():
                errors.append(f"log line {i}: genesis does not match the legacy log before it (legacy lines edited)")
        else:
            if not started:
                errors.append(f"log line {i}: chained record without a genesis (log head deleted)")
            elif rec.get("prev") != prev_entry:
                errors.append(f"log line {i}: chain break (a record before it was deleted, edited or reordered)")
            if started and rec.get("seq") != prev_seq + 1:
                errors.append(f"log line {i}: seq {rec.get('seq')} after {prev_seq} (record deleted or inserted)")
        started = True
        prev_entry, prev_seq, head = rec.get("entry"), rec.get("seq", 0), rec.get("entry")
        entries.add(head)
        typ = rec.get("type", "write")
        if typ == "anchor":
            known.update(rec.get("files", {}))
        elif typ == "write":
            rel = rec.get("file")
            if rel in known and rec.get("sha256_before") != known[rel]:
                errors.append(f"log line {i}: {rel} changed outside the tool before this write")
            known[rel] = rec.get("sha256_after")
            dpath = root / rec.get("diff", "")
            if not dpath.is_file():
                errors.append(f"log line {i}: diff file missing")
            elif rec.get("diff_sha256") and _sha_file_bytes(dpath) != rec["diff_sha256"]:
                errors.append(f"log line {i}: diff file edited")
    if expect_head and expect_head not in entries:
        errors.append("expected head not found in the chain (log truncated or rewritten since it was witnessed)")
    if check_files:
        present = dict(_memory_md_files(root))
        for rel, digest in sorted(known.items()):
            if rel not in present:
                errors.append(f"file {rel}: missing (deleted after it was logged)")
            elif _sha_file_bytes(present[rel]) != digest:
                errors.append(f"file {rel}: content differs from the last logged state (edited or entries removed)")
        for rel in sorted(set(present) - set(known)):
            warnings.append(f"file {rel}: not covered by the log yet (run `memwrite anchor`)")
    if not started:
        warnings.append("no hash chain yet (run `memwrite anchor` once)")
    return {"ok": not errors, "errors": errors, "warnings": warnings, "head": head,
            "chained_records": chained, "legacy_records": legacy, "files_tracked": len(known)}


def anchor(root: Path, agent: str, note: str = "", accept_changes: str | None = None, now=None) -> dict:
    """Record the sha256 of every memory file into the chain."""
    check_identity_and_text(agent, note or "anchor", note or "anchor", None)
    acl = load_acl(root)
    slug = resolve_agent(acl, agent)
    if acl is not None and slug is None:
        raise SystemExit(f"refused: agent '{agent}' is not in {ACL_NAME}")
    now = now or _now()
    with _RootLock(root):
        rep = verify(root)
        if rep["errors"]:
            if not accept_changes:
                raise SystemExit("refused: verify has errors; fix them or pass --accept-changes REASON "
                                 f"({len(rep['errors'])} error(s))")
            if acl is not None and slug not in acl.get("approvers", []):
                raise SystemExit("refused: only an approver may --accept-changes")
        files = {rel: _sha_file_bytes(p) for rel, p in _memory_md_files(root)}
        rec = {"type": "anchor", "time": now.isoformat(timespec="seconds"), "agent": agent,
               "note": " ".join(note.split()), "files": files}
        if accept_changes:
            rec["accepted_changes"] = " ".join(accept_changes.split())
            rec["accepted_errors"] = rep["errors"]
        rec = _chain_append(root / LOG_DIR_NAME / WRITES_LOG, rec)
    return {"status": "anchored", "files": len(files), "head": rec["entry"], "seq": rec["seq"]}


DEFAULT_ACL_SHARED = ["last-session.md", "decisions.md"]


def default_acl(bots, approvers=()) -> dict:
    return {
        "version": 1,
        "comment": "Write ACL for memwrite. Each agent may append to bots/<slug>.md, shared_writable "
                   "(unless shared: false) and its 'write' globs. owner_only files need an owner approval "
                   "from an approver. Identity is the --agent string: a guardrail, not OS isolation.",
        "owner_only": list(DEFAULT_OWNER_ONLY),
        "approvers": list(approvers),
        "shared_writable": list(DEFAULT_ACL_SHARED),
        "agents": {b: {"aliases": [], "write": []} for b in bots},
    }


# --------------------------------------------------------------------------
# init
# --------------------------------------------------------------------------

def _slugify(name: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", name.lower())).strip("-") or "item"


def _render(template: str, values: dict) -> str:
    for key, val in values.items():
        template = template.replace("{{" + key + "}}", val)
    return template


def init_tree(dest: Path, owner: str, bots, projects, now=None, acl: bool = False) -> list:
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
    acl_path = dest / ACL_NAME
    if acl and not acl_path.exists():
        slugs = [_slugify(spec.partition("=")[0]) for spec in bots]
        _write_private(acl_path, json.dumps(default_acl(slugs, [s for s in slugs if s == "brain"]), indent=2) + "\n")
        created.append(acl_path)
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
    pi.add_argument("--acl", action="store_true", help=f"also write a starter {ACL_NAME} write ACL")

    pa = sub.add_parser("append", help="append a dated block to a memory file")
    pa.add_argument("--root")
    pa.add_argument("--file", required=True)
    pa.add_argument("--agent", required=True)
    pa.add_argument("--heading", required=True)
    pa.add_argument("--text", help="block text; read from stdin if omitted")
    pa.add_argument("--id", dest="task_id")
    pa.add_argument("--dry-run", action="store_true")
    pa.add_argument("--owner-approval", metavar="TOKEN",
                    help="token from `approve`; required for owner-only files such as master/*")

    pp = sub.add_parser("approve", help="(approver only) approve one exact append to an owner-only file")
    pp.add_argument("--root")
    pp.add_argument("--file", required=True)
    pp.add_argument("--agent", required=True)
    pp.add_argument("--heading", required=True)
    pp.add_argument("--text", help="block text; read from stdin if omitted")
    pp.add_argument("--ttl-hours", type=float, default=APPROVAL_TTL_HOURS)

    pv = sub.add_parser("verify", help="check the hash-chained log, diffs and file hashes")
    pv.add_argument("--root")
    pv.add_argument("--expect-head", help="an entry hash you saved elsewhere earlier; must still be in the chain")
    pv.add_argument("--json", action="store_true")

    pn = sub.add_parser("anchor", help="record current file hashes into the chain (run once at install)")
    pn.add_argument("--root")
    pn.add_argument("--agent", required=True)
    pn.add_argument("--note", default="")
    pn.add_argument("--accept-changes", metavar="REASON",
                    help="(approver only) anchor even though verify reports errors; the errors are logged")

    ps = sub.add_parser("scan", help="check files or stdin for secrets")
    ps.add_argument("paths", nargs="+")
    ps.add_argument("--root", help="memory root whose .blocklist to apply")

    ph = sub.add_parser("hash", help="print a hashed blocklist line")
    ph.add_argument("phrase")

    args = p.parse_args(argv)

    if args.cmd == "init":
        created = init_tree(Path(args.dest).expanduser().resolve(), args.owner, args.bot, args.project, acl=args.acl)
        for c in created:
            print(f"created {c}")
        print(f"{len(created)} file(s) created. Next: replace every {{{{...}}}} and run tools/onboard_check.py")
        return 0

    if args.cmd == "append":
        root = resolve_root(args.root)
        text = args.text if args.text is not None else sys.stdin.read()
        res = append_entry(root, args.file, args.agent, args.heading, text, args.task_id, args.dry_run,
                           owner_approval=args.owner_approval)
        if res["status"] == "dry-run":
            print(res["block"])
        else:
            print(json.dumps(res))
        return 0

    if args.cmd == "approve":
        root = resolve_root(args.root)
        text = args.text if args.text is not None else sys.stdin.read()
        rec = create_approval(root, args.file, args.agent, args.heading, text, ttl_hours=args.ttl_hours)
        print(json.dumps({"status": "approved", "token": rec["token"], "file": rec["file"], "expires": rec["expires"]}))
        return 0

    if args.cmd == "verify":
        rep = verify(resolve_root(args.root), args.expect_head)
        if args.json:
            print(json.dumps(rep, indent=2))
        else:
            for e in rep["errors"]:
                print("FAIL", e)
            for w in rep["warnings"]:
                print("WARN", w)
            print(f"{'OK' if rep['ok'] else 'TAMPER/DRIFT'}: {rep['chained_records']} chained + "
                  f"{rep['legacy_records']} legacy record(s), {rep['files_tracked']} file(s) tracked, "
                  f"{len(rep['errors'])} error(s); head {rep['head']}")
        return 0 if rep["ok"] else 1

    if args.cmd == "anchor":
        print(json.dumps(anchor(resolve_root(args.root), args.agent, args.note, args.accept_changes)))
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
