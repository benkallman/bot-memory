"""Tests for memwrite and onboard_check. Standard library only.

Fake secrets are assembled at runtime so this file itself contains no
secret-looking literals for scanners to trip on.
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import memwrite  # noqa: E402
import onboard_check  # noqa: E402

D = "0123456789"
ALNUM = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5"


def fake(*parts):
    return "".join(parts)


SECRETS = {
    "github-token": fake("gh", "p_", ALNUM[:36]),
    "openai-style-key": fake("s", "k-", ALNUM[:32]),
    "aws-access-key": fake("AK", "IA", "ABCDEFGH23456789"),
    "slack-token": fake("xo", "xb-", "1234567890-abcdefghij"),
    "jwt": fake("ey", "JhbGciOiJIUzI1NiJ9", ".", "ey", "JzdWIiOiIxMjM0NTY3ODkwIn0", ".", "abcdefghijKLMNOP1234"),
    "private-key-block": fake("-----BEGIN ", "RSA PRIVATE", " KEY-----"),
    "password-value": fake("pass", "word: ", "hunter22"),
    "credential-value": fake("api", "_key = ", "Zx81Qw72Er63Ty54Ui45"),
    "otp-like-code": fake("verification code is ", D[1:7]),
    "otp-like-code-pair": fake("approved his co", "de ", "N7QK-2L8P"),
    "ssn": fake(D[1:4], "-", D[4:6], "-", D[6:10]),
    "url-credentials": fake("https://", "user", ":", "pa55w0rd", "@", "host.invalid/x"),
    "bearer-token": fake("Authorization: Bear", "er ", ALNUM[:30]),
    "payment-card-number": fake("4111", " 1111", " 1111", " 1111"),
}

CLEAN = [
    "Backfill restarted at 8:36 PM CT after the 401; checkpoint at day 2026-10-13.",
    "PR #31 merged, 44/44 tests pass, commit ab800b09.",
    "Ben types the password in the browser himself.",
    "Use the token feed endpoint; tokens expire after 3600 seconds.",
    "Status code 404 on /old-page; zip of CSVs saved.",
    "Login window opened on 2026-10-25 at 10:21 PM.",
    "Never write passwords, one-time codes or API keys into memory.",
]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "mem"
        memwrite.init_tree(self.root, "Example Owner", ["helper=Helper Bot", "scout=Shared Scout"], ["website=Website"])

    def tearDown(self):
        self.tmp.cleanup()


class TestDetection(unittest.TestCase):
    def test_each_secret_is_caught(self):
        for label, value in SECRETS.items():
            with self.subTest(label=label):
                self.assertTrue(memwrite.find_problems(f"note: {value}"), label)

    def test_clean_text_passes(self):
        for line in CLEAN:
            with self.subTest(line=line):
                self.assertEqual(memwrite.find_problems(line), [], line)

    def test_templates_are_clean(self):
        for path in (ROOT / "templates").rglob("*.md"):
            with self.subTest(path=path.name):
                self.assertEqual(memwrite.find_problems(path.read_text()), [])


class TestAppend(Base):
    def test_append_adds_block_and_keeps_old_text(self):
        target = self.root / "projects/website.md"
        before = target.read_text()
        res = memwrite.append_entry(self.root, "projects/website.md", "helper", "Deployed preview",
                                    "Preview passed 31/31 tests.")
        self.assertEqual(res["status"], "appended")
        after = target.read_text()
        self.assertTrue(after.startswith(before))
        self.assertIn("Deployed preview", after)
        self.assertIn("<!-- by: helper -->", after)

    def test_diff_and_log_written_private(self):
        res = memwrite.append_entry(self.root, "decisions.md", "helper", "Pick layout", "Decision: one file per project.")
        log = self.root / "logs/writes.jsonl"
        rec = json.loads(log.read_text().splitlines()[-1])
        self.assertEqual(rec["file"], "decisions.md")
        diff = (self.root / rec["diff"]).read_text()
        self.assertIn("+Decision: one file per project.", diff)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(log.stat().st_mode) & 0o077, 0)
            self.assertEqual(stat.S_IMODE((self.root / "logs").stat().st_mode) & 0o077, 0)
        self.assertGreater(res["bytes_added"], 0)

    def test_refuses_secret_and_writes_nothing(self):
        target = self.root / "bots/helper.md"
        before = target.read_text()
        for label, value in SECRETS.items():
            with self.subTest(label=label):
                with self.assertRaises(SystemExit) as cm:
                    memwrite.append_entry(self.root, "bots/helper.md", "helper", "x", f"saved {value}")
                self.assertIn("refused", str(cm.exception))
                self.assertNotIn(value, str(cm.exception))
        self.assertEqual(target.read_text(), before)
        self.assertFalse((self.root / "logs/writes.jsonl").exists())

    def test_idempotent_id(self):
        a = memwrite.append_entry(self.root, "registry.md", "helper", "Add row", "website active", task_id="t1")
        b = memwrite.append_entry(self.root, "registry.md", "helper", "Add row", "website active", task_id="t1")
        self.assertEqual(a["status"], "appended")
        self.assertEqual(b["status"], "skipped")
        self.assertEqual((self.root / "registry.md").read_text().count("Add row"), 1)

    def test_dry_run_writes_nothing(self):
        before = (self.root / "registry.md").read_text()
        res = memwrite.append_entry(self.root, "registry.md", "helper", "Try", "text", dry_run=True)
        self.assertEqual(res["status"], "dry-run")
        self.assertEqual((self.root / "registry.md").read_text(), before)

    def test_refuses_outside_root_non_md_missing_and_logs(self):
        for rel in ["../escape.md", "notes.txt", "projects/nope.md", "logs/writes.md"]:
            with self.subTest(rel=rel):
                with self.assertRaises(SystemExit):
                    memwrite.append_entry(self.root, rel, "helper", "x", "y")

    def test_blocklist_plain_and_hashed(self):
        (self.root / ".blocklist").write_text("# test list\nAcme Secret Project\nsha256:" +
                                              memwrite.phrase_hash("Project Nightjar") + "\n")
        for text in ["about acme secret project", "the PROJECT nightjar launch"]:
            with self.subTest(text=text):
                with self.assertRaises(SystemExit):
                    memwrite.append_entry(self.root, "registry.md", "helper", "x", text)
        res = memwrite.append_entry(self.root, "registry.md", "helper", "x", "nightjar alone is fine")
        self.assertEqual(res["status"], "appended")

    def test_cli_append_from_stdin(self):
        proc = subprocess.run([sys.executable, str(ROOT / "tools/memwrite.py"), "append", "--root", str(self.root),
                               "--file", "last-session.md", "--agent", "helper", "--heading", "Session end"],
                              input="Next: review preview.\n", text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Next: review preview.", (self.root / "last-session.md").read_text())

    def test_cli_scan_flags_secret(self):
        proc = subprocess.run([sys.executable, str(ROOT / "tools/memwrite.py"), "scan", "-"],
                              input=SECRETS["github-token"], text=True, capture_output=True)
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn(SECRETS["github-token"], proc.stdout)


class TestInit(Base):
    def test_layout_and_modes(self):
        for rel in ["master/owner.md", "master/rules.md", "registry.md", "last-session.md", "decisions.md",
                    "bots/helper.md", "bots/scout.md", "projects/website.md"]:
            self.assertTrue((self.root / rel).is_file(), rel)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE((self.root / rel).stat().st_mode), 0o600, rel)
        self.assertIn("Helper Bot", (self.root / "bots/helper.md").read_text())
        self.assertIn("Example Owner", (self.root / "master/owner.md").read_text())

    def test_init_never_overwrites(self):
        p = self.root / "registry.md"
        p.write_text("custom\n")
        memwrite.init_tree(self.root, "Other", [], [])
        self.assertEqual(p.read_text(), "custom\n")


class TestOnboardCheck(Base):
    def _fill(self):
        import re
        for p in self.root.rglob("*.md"):
            t = re.sub(r"\{\{[^}]+\}\}", "TODO", p.read_text())
            t = "\n".join(l for l in t.splitlines() if "TEMPLATE-ONLY" not in l)
            p.write_text(t + "\n")

    def test_fresh_tree_is_not_ready(self):
        rep = onboard_check.check(self.root)
        self.assertFalse(rep["ok"])
        self.assertTrue(any(e.startswith("template:") for e in rep["errors"]))

    def test_filled_tree_is_ready_and_counts_todos(self):
        self._fill()
        rep = onboard_check.check(self.root)
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertGreater(sum(rep["todos"].values()), 0)
        self.assertFalse(onboard_check.check(self.root, strict=True)["ok"])

    def test_missing_layout_and_secret_and_mode(self):
        self._fill()
        (self.root / "decisions.md").unlink()
        (self.root / "projects/website.md").write_text("<!-- access: private -->\n" + SECRETS["password-value"] + "\n")
        if os.name == "posix":
            os.chmod(self.root / "projects/website.md", 0o644)
        errs = onboard_check.check(self.root)["errors"]
        self.assertTrue(any("missing decisions.md" in e for e in errs))
        self.assertTrue(any(e.startswith("secrets:") for e in errs))
        if os.name == "posix":
            self.assertTrue(any(e.startswith("access:") for e in errs))

    def test_example_tree_is_ready(self):
        rep = onboard_check.check(ROOT / "examples/demo-memory")
        # modes are not preserved by git, so ignore access findings here
        errs = [e for e in rep["errors"] if not e.startswith("access:")]
        self.assertEqual(errs, [])


if __name__ == "__main__":
    unittest.main()
