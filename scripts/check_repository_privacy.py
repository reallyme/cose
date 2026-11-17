#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Reject local-only paths in the index, reachable history and crate contents.

Git itself evaluates ignore syntax in an isolated directory. Only policy files
are materialized: committed symlinks and file contents are never checked out.
An index snapshot prevents an unstaged ignore edit from hiding a force-add.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from enum import Enum

MAX_COMMAND_BYTES = 64 * 1024 * 1024
MAX_POLICY_BYTES = 1024 * 1024
MAX_FILES = 200_000
MAX_COMMITS = 100_000
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
BEGIN_POLICY = b"# BEGIN LOCAL-ONLY PATHS"
END_POLICY = b"# END LOCAL-ONLY PATHS"
OBJECT_ID = re.compile(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
# Integrity anchors for the minimum policy names, whose readable definitions
# live only in the root ignore file. Additional local-only names are allowed;
# removing or overriding an established private name fails closed.
REQUIRED_NAME_HASHES = frozenset({
    "b951327c37d8a1ed4d5ed18908681f6aca718ecdfe174aa39cf2237547f92fe7",
    "e026f56c08dcdea441a2aa620ab410ce91162062609b2430f5a13bc9b7cf93f1",
    "a1d1128ffe5a2849afb3ac4cad6413b6d75453babc7cac579b95c66a565fe4cc",
    "a5d2f22d1b0b7aea387ff5dc971520603f5e1a5882959beee4cf2f3a1dcd97d8",
    "1251236b0629a8f9348372ab00c4b86ad7e42cab3aa8ec32e56f7b2fb0ff8f2e",
    "2b6873defee36f1396d6a35f01c1e229cddc1db58fb19aea9bd3f7912eac5b9d",
})


class Reason(Enum):
    GIT = "repository privacy: Git inspection failed"
    POLICY = "repository privacy: missing or invalid local-only policy"
    INDEX = "repository privacy: unresolved index entries"
    PATH = "repository privacy: unsafe repository or archive path"
    LIMIT = "repository privacy: inspection resource limit"
    SHALLOW = "repository privacy: complete history is required"
    ARCHIVE = "repository privacy: invalid or unsupported archive"
    VIOLATION = "repository privacy: local-only or ignored files are tracked or packaged"
    INSTALL = "repository privacy: hook installation failed"
    HOOK = "repository privacy: hook execution failed"


class PrivacyError(Exception):
    def __init__(self, reason: Reason) -> None:
        self.reason = reason
        super().__init__(reason.value)


def clean_environment() -> dict[str, str]:
    # Hook variables such as GIT_INDEX_FILE belong to the inspected repository,
    # never to the temporary repository used to interpret ignore rules.
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def command(args: list[str], *, cwd: Path, data: bytes | None = None,
            isolated: bool = False, allowed: tuple[int, ...] = (0,)) -> bytes:
    # Files avoid pipe deadlocks when Git writes while reading a large path list.
    # Bound the result before loading it, and keep backend diagnostics private.
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as output:
        if data is not None:
            source.write(data)
            source.seek(0)
        try:
            environment = clean_environment() if isolated else dict(os.environ)
            # Replacement objects and grafts change local history views but do
            # not change the objects that a push would disclose.
            environment["GIT_NO_REPLACE_OBJECTS"] = "1"
            environment["GIT_GRAFT_FILE"] = os.devnull
            result = subprocess.run(args, cwd=cwd, stdin=source, stdout=output,
                                    stderr=subprocess.DEVNULL, check=False, timeout=120,
                                    env=environment)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PrivacyError(Reason.GIT) from error
        if result.returncode not in allowed:
            raise PrivacyError(Reason.GIT)
        if output.tell() > MAX_COMMAND_BYTES:
            raise PrivacyError(Reason.LIMIT)
        output.seek(0)
        return output.read()


def git(repository: Path, *args: str, data: bytes | None = None) -> bytes:
    repository = repository.resolve()
    return command(["git", "-C", str(repository), *args], cwd=repository, data=data)


def checked_path(path: bytes) -> str:
    if not path or b"\0" in path or b"\\" in path:
        raise PrivacyError(Reason.PATH)
    parts = path.split(b"/")
    if any(part in (b"", b".", b"..") or part.lower() == b".git" for part in parts):
        raise PrivacyError(Reason.PATH)
    return os.fsdecode(path)


@dataclass
class Snapshot:
    paths: list[bytes]
    policies: dict[bytes, bytes]


def snapshot(repository: Path, tree: str | None = None,
             blobs: dict[bytes, bytes] | None = None) -> Snapshot:
    args = ("ls-files", "--stage", "-z") if tree is None else (
        "ls-tree", "-r", "-z", "--full-tree", tree)
    records = git(repository, *args).split(b"\0")
    paths: list[bytes] = []
    policies: dict[bytes, bytes] = {}
    for record in filter(None, records):
        try:
            header, path = record.split(b"\t", 1)
            mode, middle, last = header.split(b" ")
        except ValueError as error:
            raise PrivacyError(Reason.PATH) from error
        if tree is None:
            oid = middle
            if last != b"0":
                raise PrivacyError(Reason.INDEX)
        else:
            oid = last
            if middle not in (b"blob", b"commit"):
                raise PrivacyError(Reason.PATH)
        checked_path(path)
        if not OBJECT_ID.fullmatch(oid):
            raise PrivacyError(Reason.GIT)
        paths.append(path)
        if len(paths) > MAX_FILES:
            raise PrivacyError(Reason.LIMIT)
        if path.rsplit(b"/", 1)[-1] == b".gitignore":
            if mode not in (b"100644", b"100755"):
                raise PrivacyError(Reason.POLICY)
            content = blobs.get(oid) if blobs is not None else None
            if content is None:
                content = git(repository, "cat-file", "blob", oid.decode("ascii"))
            if len(content) > MAX_POLICY_BYTES:
                raise PrivacyError(Reason.LIMIT)
            policies[path] = content
            if blobs is not None:
                blobs[oid] = content
        # A submodule has its own history and cannot be silently certified by
        # scanning the superproject's gitlink rather than its actual contents.
        if mode == b"160000":
            raise PrivacyError(Reason.PATH)
    return Snapshot(paths, policies)


def mandatory_names(policy: Snapshot) -> frozenset[str]:
    lines = policy.policies.get(b".gitignore", b"").splitlines()
    if lines.count(BEGIN_POLICY) != 1 or lines.count(END_POLICY) != 1:
        raise PrivacyError(Reason.POLICY)
    first, last = lines.index(BEGIN_POLICY), lines.index(END_POLICY)
    rules = lines[first + 1:last]
    if first >= last or b"AGENTS.md" not in rules or len(rules) < 2:
        raise PrivacyError(Reason.POLICY)
    names: set[str] = set()
    for rule in rules:
        name = rule.removesuffix(b"/")
        if not re.fullmatch(rb"[A-Za-z0-9_.-]+", name):
            raise PrivacyError(Reason.POLICY)
        names.add(name.decode("ascii").casefold())
    actual = {hashlib.sha256(name.encode("ascii")).hexdigest() for name in names}
    if not REQUIRED_NAME_HASHES.issubset(actual):
        raise PrivacyError(Reason.POLICY)
    return frozenset(names)


def ignored_paths(policy: Snapshot, paths: list[bytes], mandatory: frozenset[str]) -> set[bytes]:
    if not paths:
        return set()
    blocked = {path for path in paths if any(
        os.fsdecode(part).casefold() in mandatory for part in path.split(b"/"))}
    with tempfile.TemporaryDirectory(prefix="repository-privacy-") as directory:
        root = Path(directory)
        command(["git", "-c", "init.defaultBranch=privacy-check", "init", "--quiet",
                 "--template=", str(root)], cwd=root, isolated=True)
        for path, content in policy.policies.items():
            target = root / checked_path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        # A directory-only ignore pattern must also reject a tracked symlink
        # with that directory's name. Check its slash form without following it.
        # Prefixing keeps a literal filename beginning with ':' out of Git's
        # pathspec-magic syntax. check-ignore rejects global literal-pathspec
        # mode, so normalizing its input is necessary here.
        candidates = [b"./" + candidate for path in paths for candidate in (path, path + b"/")]
        result = command(["git", "-c", "core.excludesFile=/dev/null", "-c",
                          "core.ignoreCase=false", "check-ignore", "--no-index", "-z", "--stdin"],
                         cwd=root, data=b"\0".join(candidates) + b"\0", isolated=True,
                         allowed=(0, 1))
        blocked.update(path.removeprefix(b"./").removesuffix(b"/") for path in result.split(b"\0") if path)
    return blocked


def check_snapshot(current: Snapshot, reference: Snapshot) -> None:
    mandatory = mandatory_names(reference)
    # Apply both sets: deleting an ignore rule in the index cannot hide a file
    # still excluded by the selected reference policy, or vice versa.
    if ignored_paths(current, current.paths, mandatory) or ignored_paths(reference, current.paths, mandatory):
        raise PrivacyError(Reason.VIOLATION)


def check_working_ignores(repository: Path, paths: list[bytes]) -> None:
    if not paths:
        return
    result = command(["git", "-c", "core.excludesFile=/dev/null", "-C", str(repository), "check-ignore", "--no-index", "-z", "--stdin"],
                     cwd=repository, data=b"\0".join(b"./" + path for path in paths) + b"\0", allowed=(0, 1))
    if result:
        raise PrivacyError(Reason.VIOLATION)


def check_history(repository: Path, revision: str, reference: Snapshot) -> None:
    if git(repository, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise PrivacyError(Reason.SHALLOW)
    resolved = git(repository, "rev-parse", "--verify", "--end-of-options", revision + "^{commit}").strip()
    if not OBJECT_ID.fullmatch(resolved):
        raise PrivacyError(Reason.GIT)
    commits = git(repository, "log", "--format=%T", "--no-show-signature",
                  "--max-count=" + str(MAX_COMMITS + 1), resolved.decode("ascii")).splitlines()
    if len(commits) > MAX_COMMITS:
        raise PrivacyError(Reason.LIMIT)
    check_trees(repository, list(dict.fromkeys(commits)), reference)


def check_trees(repository: Path, trees: list[bytes], reference: Snapshot) -> None:
    # Matching depends on paths and ignore rules, not file contents. Group
    # identical policy snapshots so ordinary commits do not each initialize a
    # separate matching repository. Bound total retained paths and policy data.
    groups: dict[tuple[tuple[bytes, bytes], ...], set[bytes]] = {}
    blobs: dict[bytes, bytes] = {}
    retained_paths = 0
    retained_policy = 0
    for tree in trees:
        if not OBJECT_ID.fullmatch(tree):
            raise PrivacyError(Reason.GIT)
        current = snapshot(repository, tree.decode("ascii"), blobs)
        key = tuple(sorted(current.policies.items()))
        if key not in groups:
            groups[key] = set()
            retained_policy += sum(len(path) + len(value) for path, value in key)
        before = len(groups[key])
        groups[key].update(current.paths)
        retained_paths += len(groups[key]) - before
        if retained_paths > MAX_FILES or retained_policy > MAX_COMMAND_BYTES:
            raise PrivacyError(Reason.LIMIT)
    mandatory = mandatory_names(reference)
    all_paths: set[bytes] = set()
    for policies, paths in groups.items():
        all_paths.update(paths)
        if ignored_paths(Snapshot([], dict(policies)), list(paths), mandatory):
            raise PrivacyError(Reason.VIOLATION)
    if ignored_paths(reference, list(all_paths), mandatory):
        raise PrivacyError(Reason.VIOLATION)


def check_archive(archive: Path, prefix: str, reference: Snapshot, repository: Path | None = None) -> None:
    mapped: list[bytes] = []
    archive_policies = dict(reference.policies)
    package_roots: set[str] = set()
    archive_paths: set[str] = set()
    mandatory = mandatory_names(reference)
    total_bytes = 0
    if prefix:
        checked_path(os.fsencode(prefix))
    class BoundedReader:
        def __init__(self, source: gzip.GzipFile) -> None:
            self.source = source
            self.remaining = MAX_ARCHIVE_BYTES

        def read(self, size: int = -1) -> bytes:
            if size < 0 or size > self.remaining:
                raise PrivacyError(Reason.LIMIT)
            data = self.source.read(size)
            self.remaining -= len(data)
            return data

    try:
        with gzip.open(archive, "rb") as source, tarfile.open(fileobj=BoundedReader(source), mode="r|") as package:
            for member in package:
                total_bytes += member.size
                if member.size < 0 or total_bytes > MAX_ARCHIVE_BYTES:
                    raise PrivacyError(Reason.LIMIT)
                name = member.name.removesuffix("/")
                checked_path(os.fsencode(name))
                if name in archive_paths:
                    raise PrivacyError(Reason.ARCHIVE)
                archive_paths.add(name)
                parts = PurePosixPath(name).parts
                package_roots.add(parts[0])
                if any(part.casefold() in mandatory for part in parts):
                    raise PrivacyError(Reason.VIOLATION)
                if member.isdir() and len(parts) == 1:
                    continue
                if not (member.isfile() or member.isdir()) or len(parts) < 2 or len(mapped) >= MAX_FILES:
                    raise PrivacyError(Reason.ARCHIVE)
                relative = "/".join(parts[1:])
                path = os.fsencode(prefix + "/" + relative if prefix else relative)
                mapped.append(path)
                if member.isfile() and parts[-1] == ".gitignore":
                    if member.size > MAX_POLICY_BYTES:
                        raise PrivacyError(Reason.LIMIT)
                    content = package.extractfile(member)
                    if content is None:
                        raise PrivacyError(Reason.ARCHIVE)
                    with content:
                        archive_policies[path] = content.read(MAX_POLICY_BYTES + 1)
    except (OSError, tarfile.TarError, EOFError) as error:
        raise PrivacyError(Reason.ARCHIVE) from error
    if len(package_roots) != 1 or not mapped:
        raise PrivacyError(Reason.ARCHIVE)
    if ignored_paths(reference, mapped, mandatory) or ignored_paths(Snapshot(mapped, archive_policies), mapped, mandatory):
        raise PrivacyError(Reason.VIOLATION)
    if repository is not None:
        check_working_ignores(repository, mapped)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", action="store_true", help="inspect the staged index")
    parser.add_argument("--history", action="store_true", help="inspect all history reachable from HEAD")
    parser.add_argument("--pre-push", action="store_true", help="inspect every proposed push tip from Git stdin")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--prefix", default="", help="repository-relative package directory")
    args = parser.parse_args()
    try:
        # Strip Git's record terminator, not valid whitespace in a directory
        # name. Otherwise a neighboring clean repository could be inspected.
        root = Path(os.fsdecode(command(["git", "rev-parse", "--show-toplevel"], cwd=Path.cwd()).removesuffix(b"\n")))
        reference = snapshot(root)
        mandatory_names(reference)
        if args.index or not (args.history or args.pre_push or args.archive):
            check_snapshot(reference, reference)
            check_working_ignores(root, reference.paths)
        if args.history:
            check_history(root, "HEAD", reference)
        if args.pre_push:
            data = sys.stdin.buffer.read(MAX_COMMAND_BYTES + 1)
            if len(data) > MAX_COMMAND_BYTES:
                raise PrivacyError(Reason.LIMIT)
            for line in data.splitlines():
                fields = line.split()
                if len(fields) != 4 or not all(OBJECT_ID.fullmatch(fields[i]) for i in (1, 3)):
                    raise PrivacyError(Reason.GIT)
                if fields[1].strip(b"0"):
                    check_history(root, fields[1].decode("ascii"), reference)
        if args.archive:
            check_archive(args.archive, args.prefix, reference, root)
    except PrivacyError as error:
        print(error.reason.value, file=sys.stderr)
        return 1
    except OSError:
        print(Reason.GIT.value, file=sys.stderr)
        return 1
    print("Repository privacy checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
