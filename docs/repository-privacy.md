# Local-only files and publication

Ignored files are local state. They must not enter the Git index, commit
history, pull requests or published package contents. Adding a path with
`git add -f` does not authorize its publication.

The root `.gitignore` defines a mandatory local-only block. Its names apply
at every directory depth, including case variants and symlinks. Nested ignore
files cannot unignore those names. The guard checks the block's minimum policy
using integrity anchors, so removing a mandatory rule also fails validation.
Other ignore rules use Git's own matching and negation semantics.

The safeguards require Python 3.10 or later. Install them after cloning, and
reinstall after guard updates:

```sh
python3 scripts/install_repository_privacy_hooks.py
```

The installer stores durable hook copies in Git's common directory and selects
them with repository-local `core.hooksPath`. Existing hook files are preserved
and chained. Privacy is checked both before and after an existing hook, because
formatting hooks can change the staged index. Installed copies serve linked
worktrees and survive branch switches; a branch missing the required policy
fails closed.

The pre-commit hook checks the complete staged index, including force-added
files and staged ignore rules. Unstaged changes cannot weaken staged policy.
The pre-push hook checks all history reachable from each proposed branch or tag
tip. Deleting a private file in the latest commit does not erase earlier exposure.
Inspection never deletes local files or rewrites commits.

Run the same checks directly:

```sh
python3 scripts/check_repository_privacy.py --index --history
python3 -m unittest discover -s scripts -p test_repository_privacy.py
```

Complete history is required. Shallow clones, unresolved index entries, unsafe
policy files and submodules fail closed rather than producing an incomplete
privacy certification. Submodule histories require a separately reviewed policy.

The Repository Privacy workflow checks pushes, pull requests and merge groups.
Release-readiness checks enforce the index policy. Crate inspection and
publication check reachable history and archive entries before copying,
extracting or publishing packages. Archive paths are mapped back to the source
package directory so nested ignore rules apply. Path traversal, links, multiple
archive roots and excessive archive expansion are rejected without extraction.
Build artifacts may be stored in ignored build directories; their published
contents must satisfy the source privacy policy.

Local hooks can be bypassed with `--no-verify` or a changed Git configuration.
CI runs after a commit reaches the hosting service. A required CI check can
block merging or release, but cannot undo that initial upload. Server-side
write restrictions and a trusted admission process are necessary for a strict
pre-upload guarantee. Repository administrators must configure those controls;
adding this workflow does not change server settings.

If exposure occurs, rotate affected credentials immediately. Removing a file
from the index preserves local contents but does not remove old commits.
History rewriting, replacement tags and force pushes require a coordinated
plan and explicit approval. Hosted PR refs, caches, forks, archives and other
clones may retain old data, so complete removal cannot be guaranteed.
