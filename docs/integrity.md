# Write ACLs, owner approvals and tamper evidence

## What runs on every write

`memwrite append` takes one lock per memory root (`logs/.write.lock`, flock)
and, while holding it: checks `--id` against the log, appends the block, writes
the diff, and appends one hash-chained record to `logs/writes.jsonl`. One lock
means one linear history, so `--id` cannot be applied twice and the chain
cannot fork. The cost is a few milliseconds per write; nothing extra runs when
bots only read memory.

## Write ACLs (`ROOT/.acl.json`, optional)

```json
{
  "version": 1,
  "owner_only": ["master/*"],
  "approvers": ["brain"],
  "shared_writable": ["last-session.md", "decisions.md"],
  "agents": {
    "brain":  {"aliases": ["Brain"], "write": ["*"]},
    "helper": {"aliases": ["Helper Bot"], "write": ["projects/website.md"]},
    "scout":  {"shared": false, "write": []}
  }
}
```

* `--agent` is turned into a slug (`"Helper Bot (executor)"` -> `helper-bot`)
  and matched against agent slugs and aliases. Unknown agents are refused when
  the file exists.
* An agent may append to `bots/<slug>.md`, to `shared_writable` (unless
  `"shared": false`), and to its `write` globs.
* `owner_only` files (default `master/*`, enforced even with no ACL file) need
  an owner approval. `"*"` does not cover them.
* Agent names `owner`, `ben`, `system`, `root`, `memwrite` are reserved.
* Text containing `<!-- by: ... -->`, `<!-- id: -->`, `<!-- access: -->`,
  `<!-- owner: -->` style markers, or a line shaped like a block heading
  (`### 2026-01-01 09:00 ...`), is refused, as is markup in `--agent`,
  `--heading` or `--id`. Only the tool writes block metadata.

`memwrite init DIR --acl ...` writes a starter `.acl.json`.

## Owner approvals

```bash
# Approver (e.g. brain), after the owner says yes to the exact text:
python3 tools/memwrite.py approve --root R --file master/rules.md --agent brain \
  --heading "New rule" --text "..."          # prints {"token": "appr-..."}
python3 tools/memwrite.py append  --root R --file master/rules.md --agent brain \
  --heading "New rule" --text "..." --owner-approval appr-...
```

The token is bound to the file and to the exact heading and text, expires
after 24 h (`--ttl-hours`), works once, and is logged in the chain. The block
carries `owner-approved: <token>`.

## Hash chain and `verify`

Each new record in `logs/writes.jsonl` has `seq`, `prev` (the previous record's
`entry`) and `entry` = sha256 of its own canonical JSON. Write records also hold
`sha256_before/after` of the file, `content_sha256` of the appended text and
`diff_sha256`. The first chained record (genesis) sets `prev` to the sha256 of
all older, unchained log lines, so those are pinned too.

`memwrite anchor --agent NAME` records the sha256 of every memory file. Run it
once when you install this version, and again (it refuses if verify fails,
unless an approver passes `--accept-changes REASON`) after creating new files.

`memwrite verify [--expect-head HASH]` reports, without printing any memory
text:

* edited, deleted, inserted or reordered log lines; a second genesis;
* diff files that are missing or edited;
* memory files that differ from their last logged state (hand edits or removed
  entries) or are missing; files not covered yet are warnings;
* with `--expect-head`, a truncated or rewritten log (the saved head is gone).

Deleting the newest log lines and reverting the files to match is only
detectable against a head you saved somewhere else. Save `verify`'s head
outside the box (or in a place the bots cannot write) from time to time.

`onboard_check.py --verify` runs the same check. It is off by default so the
routine check stays cheap; run it when you need it, not every turn.

## Limits (same OS user)

Every bot on a single-user box runs as the same UID, so any of them can:

* edit or delete memory files, the log, the diffs, `.acl.json` and approval
  tokens directly, without using the tool;
* pass any `--agent` string (identity is a claim, not a credential);
* run `approve` as an approver name.

So ACLs and approvals are guardrails for bots that follow their instructions,
and against prompt-injected text that tries to forge owner entries. The chain
makes silent edits visible, but a writer that knows the format can rebuild a
consistent chain after editing; only a head saved elsewhere catches that.

Optional HMAC: set `MEMWRITE_HMAC_KEY_FILE` to a key file and every new record
gets `mac` = HMAC-SHA256(key, entry); `verify` with the same key checks them.
If the key is readable by the same UID as the bots, it only stops tools and
bots that do not look for it. Real separation needs different OS users (or
containers) per bot, the log on storage the bots cannot write, or an external
witness for the chain head.

## Secret filter

Pattern-based, refuses and names the rule only. Covers private key blocks
(PEM, OpenSSH, PGP, PuTTY), GitHub, GitLab, npm, Hugging Face, Slack (tokens,
app tokens, webhooks), AWS access and secret keys, Google API and OAuth,
OpenAI / Anthropic / OpenRouter `sk-` styles, xAI, Stripe, Telegram bot tokens,
JWTs, bearer tokens, URL credentials, `888k1` recovery keys, password values
(including `pw for <site>: <value>` and `passwd <value>`), long values after
key/secret/token words, SSNs and card numbers.

One-time codes: 6-8 digits (or `123 456`) a few words after a code word
(code, OTP, 2FA, verification, PIN, ...); 4-5 digits only with a strong word and
an explicit `is`, `:` or `=` right after the word. `Code 2026 release plan` and
`PIN 1234 is the gate number` pass. It still misses secrets with no recognisable
shape; keep secrets in a vault.
