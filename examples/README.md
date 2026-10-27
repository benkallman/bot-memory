# Example memory tree

`demo-memory/` is what `memwrite init` produces after an owner fills it in, for
a made-up owner "Alex Example" with two bots and one project. `scout` is a
shared bot: its file and the one project it may read are marked
`<!-- access: shared -->`. Run `python3 tools/onboard_check.py examples/demo-memory`.
(Git does not keep file modes, so a fresh clone may report `access:` findings;
fix them with `chmod 600`.)
