# bot-memory

Plain-markdown memory for a team of AI agents (bots) that work for one person.
No database, no service, no dependencies: a folder of `.md` files, one small
append-only writer, and a readiness check. Any agent that can read files and
run `python3` can use it.

## Why

Agents forget between sessions, repeat dead ends, and quietly undo decisions.
This layout fixes that with a few habits that worked in practice:

| Pattern | File | What it prevents |
|---|---|---|
| Project registry | `registry.md` | Agents guessing what exists |
| Pause / resume handoff | `last-session.md` | Starting cold every session |
| Frozen-work handoff with proven-evidence table and "dead branches, do not reopen" | `templates/frozen-handoff.md` | Re-trying what already failed; claiming what was never proven |
| Decisions log with "do not reverse unless" | `decisions.md` | Quiet reversals |
| Onboarding check | `tools/onboard_check.py` | Template text left in place, stale copies from another project |
| Append-only writer that refuses secrets and logs diffs | `tools/memwrite.py` | Lost history, leaked credentials |
| Loop state with one next recommended action | `templates/loop-state.md` | Routines that drift |

More on each in [docs/patterns.md](docs/patterns.md).

## Layout

```
<memory root>/
  master/            owner profile + standing rules (private)
    owner.md
    rules.md
  bots/<bot>.md      one file per bot: job, what it reads, what it owns, log
  projects/<p>.md    one file per project: goal, status, evidence, next action
  registry.md        every project and bot, one row each
  last-session.md    newest handoff block at the bottom
  decisions.md       append-only decisions
  logs/              written by memwrite only (diffs + writes.jsonl), private
  .blocklist         optional phrases memwrite must refuse (never commit it)
```

## Quick start (people)

```bash
git clone https://github.com/benkallman/bot-memory
cd bot-memory
python3 tools/memwrite.py init ~/bot-memory --owner "Your Name" \
  --bot helper="Helper Bot" --bot research="Research Bot" \
  --project website="Website"
# edit the files: replace every {{...}} with a fact, or with TODO if unknown
python3 tools/onboard_check.py ~/bot-memory
```

`init` never overwrites an existing file, and creates files with mode 600 and
folders with mode 700.

## Quick start (bots)

Give each bot this instruction (edit the paths):

> At the start of work, read `~/bot-memory/master/owner.md`, `master/rules.md`,
> your own `bots/<your-slug>.md`, the newest block of `last-session.md`, and
> each `projects/<slug>.md` your bot file lists. Never edit memory files by hand.
> To record something, run
> `python3 <repo>/tools/memwrite.py append --root ~/bot-memory --file <rel path> --agent <your-slug> --heading "<short title>" --text "<facts>"`.
> At the end of a session, append a handoff block to `last-session.md`.
> Record decisions in `decisions.md` with a "Do not reverse unless" line.

## Rules lock

`master/rules.md` is the single source of truth for the owner's standing rules.

- Every bot reads `master/rules.md` first, at the start of every turn. It overrides any conflicting entry in the platform's shared memory or a bot's own notes.
- Bots never edit it. `master/*` is owner-only in `.acl.json`: an append needs a one-time approval from the designated approver bot (`memwrite.py approve`), and the approver acts only on the owner's own words, never on another bot's claim that the owner agreed.
- Each bot's profile carries the same instruction, so the lock holds even if a bot skips the docs.
- `memwrite.py verify` detects any edit made outside the writer.

## The writer

```bash
python3 tools/memwrite.py append --root ~/bot-memory --file projects/website.md \
  --agent helper --heading "Deployed preview" --id run-42 \
  --text "Preview build passed 31/31 tests. Next: owner review."
```

* Appends one dated block to the end of an existing `.md` file inside the root. Never rewrites.
* Refuses (and writes nothing) when the text looks like a password, API key or
  token, private key, JWT, URL with credentials, one-time or verification code,
  SSN-style number, or payment card number, or matches `.blocklist`.
  The refusal names the rule and line, never the value.
* Writes a unified diff to `logs/diffs/` and a JSON line to `logs/writes.jsonl`.
* `--id` makes a write idempotent: the same id on the same file is skipped.
  The check runs inside the root-wide write lock (`logs/.write.lock`), so it
  holds under many concurrent writers.
* Each log line is hash-chained to the one before it (`memwrite verify`
  detects edited, deleted, inserted or reordered log lines, edited diffs, and
  memory files changed outside the tool).
* Optional write ACLs in `ROOT/.acl.json`: which agent may append to which
  files. `master/*` is owner-only by default and needs a one-time
  `memwrite approve` token from an approver. Text that tries to forge block
  metadata (`<!-- by: ... -->`, fake `### date | heading` lines) is refused.
* `--dry-run` shows the block without writing.

Other commands: `scan FILE...` (check files or `-` for stdin),
`hash "phrase"` (prints a `sha256:` line for `.blocklist`, so you can block a
name without writing the name down), `approve`, `verify` and `anchor`
(see [docs/integrity.md](docs/integrity.md)).

The checks are pattern-based. They catch common mistakes, not a determined
leak. Keep secrets in a real secret manager.

## Shared bots

If another person also uses one of your bots, that bot should read only its own
bot file and the project files you allow in it. Mark everything else
`<!-- access: private -->` and keep it mode 600. The onboarding check flags
private files that are group or world readable. File modes only separate
different OS users; if every bot runs as the same user, the rule in the bot
file is what keeps it out. See [docs/shared-bots.md](docs/shared-bots.md).

The same limit applies to the ACLs and the hash chain: any process running as
the same OS user can edit files directly, bypassing the tool. They stop
mistakes and instruction-following bots and make tampering visible; they are
not isolation. See [docs/integrity.md](docs/integrity.md).

## Tests

```bash
python3 -m unittest discover -s tests -v
python3 tests/stress_concurrency.py 22 50 3   # 22 writers, 1100 appends, 66 same-id attempts
```

## License

MIT, see [LICENSE](LICENSE).
