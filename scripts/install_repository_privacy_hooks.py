#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Install durable local hooks without replacing any existing hook files."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from check_repository_privacy import PrivacyError, Reason


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, check=False)
    if result.returncode != 0:
        raise PrivacyError(Reason.INSTALL)
    return result.stdout.removesuffix("\n")


def replace(path: Path, content: bytes, mode: int) -> None:
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temporary.write(content)
        name = temporary.name
    try:
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    root = Path(git("rev-parse", "--show-toplevel")).resolve()
    common = Path(git("rev-parse", "--path-format=absolute", "--git-common-dir"))
    destination = common / "repository-privacy-hooks"
    state_path = destination / "installation.json"
    if destination.is_symlink():
        raise PrivacyError(Reason.INSTALL)
    if destination.exists():
        if not state_path.is_file():
            raise PrivacyError(Reason.INSTALL)
        state = json.loads(state_path.read_text())
        if (not isinstance(state, dict) or type(state.get("version")) is not int
                or state.get("version") != 1 or not isinstance(state.get("previous"), dict)):
            raise PrivacyError(Reason.INSTALL)
        for name, value in state["previous"].items():
            if name not in ("pre-commit", "pre-push") or not isinstance(value, str) or not Path(value).is_absolute():
                raise PrivacyError(Reason.INSTALL)
    else:
        previous = Path(git("rev-parse", "--path-format=absolute", "--git-path", "hooks"))
        if not previous.is_absolute():
            previous = (root / previous).resolve()
        state = {"version": 1, "previous": {
            name: str(previous / name) for name in ("pre-commit", "pre-push")
            if (previous / name).is_file() and os.access(previous / name, os.X_OK)
        }}
        destination.mkdir(mode=0o700)
    # The installed copies survive branch switches and serve all linked
    # worktrees. Git still supplies the active worktree and staged index.
    for name in ("check_repository_privacy.py", "run_repository_privacy_hook.py"):
        replace(destination / name, (root / "scripts" / name).read_bytes(), 0o600)
    hook = b'''#!/bin/sh
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
# SPDX-License-Identifier: MIT OR Apache-2.0
set -eu
hook_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$hook_directory/run_repository_privacy_hook.py" "$(basename -- "$0")" "$@"
'''
    for name in ("pre-commit", "pre-push"):
        replace(destination / name, hook, 0o700)
    replace(state_path, (json.dumps(state) + "\n").encode(), 0o600)
    git("config", "--local", "core.hooksPath", str(destination))
    print("Repository privacy hooks installed; existing hooks are chained.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, PrivacyError, ValueError, TypeError):
        print("repository privacy: hook installation failed", file=sys.stderr)
        sys.exit(1)
