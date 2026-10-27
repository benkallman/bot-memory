<!-- access: private -->
# Decisions log

Append-only. One block per decision. Do not edit or delete past decisions; add a new one that supersedes.
Each block: Decision, Why, Decided by, Do not reverse unless, Supersedes.


## Decisions (append-only, newest at bottom)

### 2026-01-01 09:00 +0000 | One file per project
<!-- by: helper; id: demo-1 -->
Decision: Keep one markdown file per project.
Why: Bots load only what the task needs.
Decided by: owner
Do not reverse unless: lookups get slow past 200 projects.
Supersedes: none
