# Changes

## 2026-10-27 - hardening

* **Fix: `--id` race.** The dedupe check ran before the file lock, so parallel
  writers with the same id could all append (12-19 duplicates out of 66
  attempts with 22 writers). All writes now hold one root-wide lock
  (`logs/.write.lock`) across dedupe, append, diff and log. Stress test
  (`tests/stress_concurrency.py 22 50 3`): 1 of 66 same-id attempts appended,
  1100/1100 blocks intact, chain verifies.
* **Write ACLs** (`ROOT/.acl.json`, optional): agent -> writable files.
  `master/*` is owner-only (even without an ACL file) and needs a one-time,
  content-bound `memwrite approve` token from an approver. Forged
  `<!-- by: owner -->` style markers, fake block headings, reserved agent names
  (`owner`, `ben`, ...) and markup in `--agent/--heading/--id` are refused.
* **Tamper evidence:** `logs/writes.jsonl` records are now hash-chained
  (`seq`, `prev`, `entry`, plus `content_sha256` and `diff_sha256`). New
  `memwrite verify` and `memwrite anchor`; `onboard_check.py --verify`.
  Optional HMAC via `MEMWRITE_HMAC_KEY_FILE`. Old log lines are kept unchanged
  and pinned by the first chained record.
* **Secret filter:** more token formats (GitHub fine-grained, AWS secret keys,
  Slack app tokens and webhooks, Google OAuth, Anthropic/xAI/OpenRouter keys,
  Hugging Face, Telegram, PGP/PuTTY keys, `888k1` recovery keys, `pw for X:`,
  `passwd value`). Fewer one-time-code false positives: 6-8 digits near a code
  word; 4-5 digits only with `PIN is`/`OTP:` style phrasing.
* **Docs:** `docs/integrity.md`, including the same-OS-user limit: ACLs, approvals
  and the chain are guardrails and evidence, not isolation.
* Tests: 18 existing + 15 new (`tests/test_hardening.py`).

Upgrade: run `memwrite anchor --root R --agent <approver>` once; add
`.acl.json` if you want per-agent limits; approvers use `approve` +
`--owner-approval` for `master/*`.
