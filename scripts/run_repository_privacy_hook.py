#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Check before and after an existing hook, preserving its arguments and stdin."""

import json
import os
from pathlib import Path
import subprocess
import sys

from check_repository_privacy import MAX_COMMAND_BYTES, Reason


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("pre-commit", "pre-push"):
        return 1
    directory = Path(__file__).resolve().parent
    state = json.loads((directory / "installation.json").read_text())
    if (not isinstance(state, dict) or type(state.get("version")) is not int
            or state.get("version") != 1 or not isinstance(state.get("previous"), dict)):
        return 1
    name = sys.argv[1]
    data = sys.stdin.buffer.read(MAX_COMMAND_BYTES + 1) if name == "pre-push" else b""
    if len(data) > MAX_COMMAND_BYTES:
        return 1
    options = ["--pre-push"] if name == "pre-push" else ["--index"]
    checker = [sys.executable, str(directory / "check_repository_privacy.py"), *options]
    checked = subprocess.run(checker, input=data, check=False)
    if checked.returncode:
        return checked.returncode
    previous = state.get("previous", {}).get(name)
    if previous is not None:
        if not isinstance(previous, str) or not Path(previous).is_absolute() or not os.access(previous, os.X_OK):
            return 1
        if Path(previous).resolve().parent == directory:
            return 1
        result = subprocess.run([previous, *sys.argv[2:]], input=data, check=False)
        if result.returncode:
            return result.returncode
        # Formatting and policy hooks can stage additional files. Check their
        # final index too, rather than trusting the initial admission result.
        return subprocess.run(checker, input=data, check=False).returncode
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError):
        print(Reason.HOOK.value, file=sys.stderr)
        sys.exit(1)
