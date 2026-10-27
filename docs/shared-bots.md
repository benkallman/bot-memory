# Shared bots and access tiers

Some bots are used by more than one person (for example a bot a collaborator
also talks to). Treat such a bot as outside the owner's private circle.

1. Its bot file says, at the top, which files it may read. Usually: its own bot
   file, `HOW-BOTS-USE-THIS.md` (or your equivalent), and named project files.
2. It never reads `master/`, other bots' files, `registry.md`, `last-session.md`
   or `decisions.md`, since those mix topics.
3. Private files start with `<!-- access: private -->` and are mode 600; private
   folders are mode 700. Files a shared bot may read are marked
   `<!-- access: shared -->`.
4. Other bots must not copy private details into shared files. Run
   `memwrite scan` on anything before it goes into a shared file.

File permissions only separate different operating-system users. If all bots
run as one user, permissions are a label, and the written rule is the control.
Run the shared bot as its own OS user if you need hard separation.
