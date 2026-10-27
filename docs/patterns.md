# Patterns

These came from running many agent projects with markdown memory and seeing
what held up and what rotted.

## 1. One registry
`registry.md` lists every project and bot with status and location. An agent
that cannot find a project in the registry should ask, not invent one.

## 2. Pause / resume handoff (`last-session.md`)
At the end of every session the agent appends a block: what changed, files,
verification, status, the single next step, what waits on the owner. The next
agent reads only the newest block to resume.

## 3. Frozen-work handoff
When work stops unfinished, write a page from `templates/frozen-handoff.md`:
objective, why it froze, a table of what is proven (with evidence), what is not
proven, and "dead branches, do not reopen" with the reason each failed. This is
what stops the next agent repeating a failed approach.

## 4. Decisions with "do not reverse unless"
Each decision records why and the specific condition under which it may be
revisited. Agents must not reverse a decision unless that condition is met; they
add a new superseding decision instead of editing the old one.

## 5. Onboarding check
Copying a memory layout from another project leaves stale text behind. The
check fails while any `{{placeholder}}` or `TEMPLATE-ONLY` text remains, scans
for secrets, and checks private file modes. `TODO` is allowed and counted: an
honest gap is better than an invented fact.

## 6. Append-only writer
Agents never hand-edit memory. `memwrite append` adds a dated, signed block,
refuses secret-looking text, logs a diff, and supports idempotent ids. History is
never lost, and every change is reviewable.

## 7. Loop state
Routines keep `loop-state.md`: status, blockers, backlog, exactly one "next
recommended action", and an append-only cycle history.

## Rules of thumb
* Facts only. Prefix inferences with `guess:`. Unknowns are `TODO`.
* No "done" without proof (command output, commit, URL, test result).
* One file per project; load only what the task needs.
