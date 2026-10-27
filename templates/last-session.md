<!-- access: private -->
# Last session (pause / resume handoff)

Append one block at the end of every work session. The newest block at the bottom is the current handoff.
Each block answers: what changed, files touched, verification, current status, next step, what is waiting on the owner.

Block shape (copy into the `--text` of `memwrite append`):

    Bot: <slug> · Project: <slug>
    Changed: <one line>
    Files: <paths>
    Verified: <command and result>
    Status: <ACTIVE | BLOCKED | DONE>
    Next: <single next action>
    Waiting on owner: <item or "nothing">

## Sessions (append-only, newest at bottom)
