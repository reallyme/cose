# Local-only files and publication

Anything matching repository `.gitignore` rules must stay out of Git tracking,
PRs and published packages, including files added with `git add -f`. The
mandatory local-only names apply at every directory depth and cannot be
unignored by nested rules.

Install the local hooks after cloning and reinstall after guard updates.
Python 3.10 or later is required:

```sh
python3 scripts/install_repository_privacy_hooks.py
```

The installer preserves and chains existing hooks. Installed hooks serve linked
worktrees and survive branch switches. Pre-commit checks the staged index;
pre-push checks history reachable from the proposed tips. Neither deletes local
files nor rewrites history. A branch missing the mandatory policy is rejected.

To check manually, fetch complete history first, then run:

```sh
python3 scripts/check_repository_privacy.py --index --history
python3 -m unittest discover -s scripts -p test_repository_privacy.py
```

The CI check is `No local-only tracked or packaged files`. The supported crate
publication scripts also inspect archive contents. Shallow history, unresolved
index entries, unsafe policy files and submodules fail validation.

Local hooks can be bypassed and CI runs after upload. Administrators must control
server-side write access and publishing credentials for a strict pre-upload
guarantee; installing these files does not configure remote protections.

If a secret is exposed, rotate it immediately. Deleting a file at the branch tip
does not remove older commits. Coordinate and approve any history rewrite,
replacement tag or force push. Hosted PR refs, caches, forks, archives and clones
can retain old data; complete removal cannot be guaranteed.
