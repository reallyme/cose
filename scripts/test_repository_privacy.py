# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Disposable-repository tests; no network, live ref edits or publication."""

from __future__ import annotations

import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parent
POLICY = (SOURCE.parent / ".gitignore").read_bytes()
LOCAL_NAMES = POLICY.split(b"# BEGIN LOCAL-ONLY PATHS\n", 1)[1].split(b"# END LOCAL-ONLY PATHS", 1)[0].splitlines()
CHECK = SOURCE / "check_repository_privacy.py"


class PrivacyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="repository-privacy-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.git("init", "--quiet", "--template=", "--initial-branch=privacy-test")
        (self.root / ".gitignore").write_bytes(POLICY + b"\nprivate/\n*.scratch\n!public.scratch\n")
        self.git("add", ".gitignore")

    def git(self, *args: str, data: bytes | None = None) -> bytes:
        return subprocess.check_output(["git", *args], cwd=self.root, input=data,
                                       stderr=subprocess.DEVNULL)

    def check(self, *args: str, data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run([sys.executable, str(CHECK), *args], cwd=self.root,
                              input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    def write(self, name: str, content: bytes = b"synthetic local data") -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def commit_object(self, parent: bytes | None = None) -> bytes:
        # Reuse existing repository authorship verbatim rather than creating
        # invented identities or changing the operator's Git configuration.
        original = subprocess.check_output(["git", "cat-file", "commit", "HEAD"], cwd=SOURCE.parent)
        identity = b"\n".join(line for line in original.split(b"\n\n", 1)[0].splitlines()
                              if line.startswith((b"author ", b"committer ")))
        tree = self.git("write-tree").strip()
        raw = b"tree " + tree + b"\n"
        if parent:
            raw += b"parent " + parent + b"\n"
        raw += identity + b"\n\nRepository privacy test fixture\n"
        commit = self.git("hash-object", "-t", "commit", "-w", "--stdin", data=raw).strip()
        self.git("update-ref", "HEAD", commit.decode())
        return commit

    def test_clean_index_and_negation_are_allowed(self) -> None:
        self.write("public.scratch")
        self.git("add", "public.scratch")
        self.assertEqual(self.check().returncode, 0)
        self.write(":literal")
        self.git("--literal-pathspecs", "add", "--", ":literal")
        self.assertEqual(self.check().returncode, 0)

    def test_every_mandatory_name_is_blocked_at_every_depth_and_case(self) -> None:
        for raw in LOCAL_NAMES:
            name = raw.decode().removesuffix("/")
            for path in [name + "/data" if raw.endswith(b"/") else name,
                         "nested/" + name.upper() + "/data"]:
                with self.subTest(path=path):
                    local = self.write(path)
                    self.git("add", "-f", "--", path)
                    self.assertNotEqual(self.check().returncode, 0)
                    self.assertEqual(local.read_bytes(), b"synthetic local data")
                    self.git("rm", "--cached", "--", path)

    def test_staged_policy_cannot_be_bypassed_by_unstaged_ignore_changes(self) -> None:
        self.write("private/value")
        self.git("add", "-f", "private/value")
        (self.root / ".gitignore").write_bytes(POLICY)
        self.assertNotEqual(self.check().returncode, 0)

    def test_repository_directory_whitespace_cannot_select_a_neighboring_index(self) -> None:
        for name in ["neighbor", "neighbor "]:
            root = self.root / name
            root.mkdir()
            subprocess.run(["git", "init", "--quiet", "--template="], cwd=root, check=True)
            (root / ".gitignore").write_bytes(POLICY + b"\nprivate/\n")
            subprocess.run(["git", "add", ".gitignore"], cwd=root, check=True)
        private = self.root / "neighbor " / "private" / "value"
        private.parent.mkdir()
        private.write_bytes(b"synthetic local data")
        subprocess.run(["git", "add", "-f", "private/value"], cwd=self.root / "neighbor ", check=True)
        result = subprocess.run([sys.executable, str(CHECK)], cwd=self.root / "neighbor ",
                                capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_nested_negation_cannot_unignore_a_mandatory_name(self) -> None:
        name = LOCAL_NAMES[1].decode().removesuffix("/")
        self.write("nested/.gitignore", ("!" + name + "/\n!" + name + "/**\n").encode())
        path = "nested/" + name + "/data"
        self.write(path)
        self.git("add", "nested/.gitignore")
        self.git("add", "-f", path)
        self.assertNotEqual(self.check().returncode, 0)

    def test_symlinks_and_newline_names_do_not_bypass_policy(self) -> None:
        target = self.write("public")
        os.symlink(target, self.root / "private")
        self.git("add", "-f", "private")
        self.assertNotEqual(self.check().returncode, 0)
        self.git("rm", "--cached", "private")
        self.write("line\nbreak.scratch")
        self.git("add", "-f", "--", "line\nbreak.scratch")
        self.assertNotEqual(self.check().returncode, 0)

    def test_minimum_policy_cannot_be_removed(self) -> None:
        (self.root / ".gitignore").write_bytes(POLICY.replace(LOCAL_NAMES[1] + b"\n", b""))
        self.git("add", ".gitignore")
        self.assertNotEqual(self.check().returncode, 0)

    def test_pre_push_rejects_historical_exposure_even_after_tip_deletion(self) -> None:
        clean = self.commit_object()
        self.write("private/value")
        self.git("add", "-f", "private/value")
        exposed = self.commit_object(clean)
        self.git("rm", "--cached", "private/value")
        tip = self.commit_object(exposed)
        self.assertEqual(self.check().returncode, 0)
        self.assertNotEqual(self.check("--history").returncode, 0)
        records = b"refs/heads/privacy-test " + tip + b" refs/heads/privacy-test " + b"0" * 40 + b"\n"
        self.assertNotEqual(self.check("--pre-push", data=records).returncode, 0)
        self.assertTrue((self.root / "private/value").exists())

    def test_empty_historical_trees_do_not_become_empty_git_path_arguments(self) -> None:
        self.git("rm", "--cached", ".gitignore")
        self.commit_object()
        self.git("add", ".gitignore")
        self.assertEqual(self.check("--history").returncode, 0)

    def test_local_replacement_objects_cannot_hide_pushed_history(self) -> None:
        clean = self.commit_object()
        self.write("private/value")
        self.git("add", "-f", "private/value")
        exposed = self.commit_object(clean)
        self.git("rm", "--cached", "private/value")
        self.commit_object(exposed)
        self.git("replace", exposed.decode(), clean.decode())
        self.assertNotEqual(self.check("--history").returncode, 0)

    def test_archive_is_inspected_without_extracting_or_following_links(self) -> None:
        archive = self.root / "package.crate"
        for name, allowed in [("package/src/lib.rs", True), ("package/private/value", False),
                              ("package/../escape", False), ("package/AGENTS.md", False)]:
            with self.subTest(name=name):
                with tarfile.open(archive, "w:gz") as package:
                    entry = tarfile.TarInfo(name)
                    entry.size = 1
                    package.addfile(entry, io.BytesIO(b"x"))
                self.assertEqual(self.check("--archive", str(archive)).returncode == 0, allowed)
        self.assertFalse((self.root / "escape").exists())

    def test_packaged_ignore_rules_and_archive_links_cannot_bypass_admission(self) -> None:
        archive = self.root / "package.crate"
        with tarfile.open(archive, "w:gz") as package:
            for name, data in [("package/.gitignore", b"hidden.txt\n"), ("package/hidden.txt", b"x")]:
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                package.addfile(entry, io.BytesIO(data))
        self.assertNotEqual(self.check("--archive", str(archive), "--prefix", "source").returncode, 0)
        with tarfile.open(archive, "w:gz") as package:
            entry = tarfile.TarInfo("package/source/link")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "../../outside"
            package.addfile(entry)
        self.assertNotEqual(self.check("--archive", str(archive)).returncode, 0)
        with tarfile.open(archive, "w:gz") as package:
            for _ in range(2):
                entry = tarfile.TarInfo("package/source/repeated")
                entry.size = 1
                package.addfile(entry, io.BytesIO(b"x"))
        self.assertNotEqual(self.check("--archive", str(archive)).returncode, 0)

    def test_installed_hooks_chain_existing_hooks_and_recheck_the_final_index(self) -> None:
        (self.root / "scripts").mkdir()
        for name in ["check_repository_privacy.py", "run_repository_privacy_hook.py", "install_repository_privacy_hooks.py"]:
            shutil.copyfile(SOURCE / name, self.root / "scripts" / name)
        previous = self.root / ".git/hooks/pre-commit"
        previous.parent.mkdir(parents=True, exist_ok=True)
        previous.write_text("#!/bin/sh\ngit add -f private/value\n")
        previous.chmod(0o700)
        self.write("private/value")
        result = subprocess.run([sys.executable, "scripts/install_repository_privacy_hooks.py"],
                                cwd=self.root, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        hook = subprocess.run(["git", "hook", "run", "pre-commit"], cwd=self.root,
                              capture_output=True, check=False)
        self.assertNotEqual(hook.returncode, 0)
        self.assertTrue(previous.exists())
        self.assertTrue((self.root / "private/value").exists())


if __name__ == "__main__":
    unittest.main()
