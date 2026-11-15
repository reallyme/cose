// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("./publish_crates_in_order.mjs", import.meta.url));

function runFixture({ mode = "publish", scenario = "success", requirement = "^0.2.2", version = "0.2.2", archive = undefined } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "cose-publish-test-"));
  try {
    const callsPath = join(directory, "calls.json");
    const reviewed = join(directory, "reviewed");
    if (archive !== undefined) {
      mkdirSync(reviewed);
      for (const name of ["reallyme-cose", "reallyme-cose-proto"]) {
        writeFileSync(join(reviewed, `${name}-${version}.crate`), archive);
      }
    }
    const preload = join(directory, "mock.mjs");
    // Intercept every child process: these tests must never invoke Cargo,
    // access a registry, publish a crate, or perform real retry waits.
    writeFileSync(preload, `
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const calls = [];
const scenario = ${JSON.stringify(scenario)};
let attempts = 0;
Atomics.wait = (_array, _index, _value, delay) => {
  calls.push(["wait", delay]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  return "timed-out";
};
childProcess.spawnSync = (command, args) => {
  calls.push([command, ...args]);
  writeFileSync(${JSON.stringify(callsPath)}, JSON.stringify(calls));
  const ok = { status: 0, stdout: "", stderr: "" };
  if (command === "curl") {
    const remote = scenario === "registry-mismatch" ? "changed registry bytes" : "reviewed bytes";
    writeFileSync(args[args.indexOf("--output") + 1], remote);
    return ok;
  }
  if (command !== "cargo") return { ...ok, status: 99 };
  if (args[0] === "metadata") return { ...ok, stdout: JSON.stringify({
    target_directory: ${JSON.stringify(directory)},
    packages: [
      { name: "reallyme-cose", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [{ name: "reallyme-cose-proto", source: null, path: "crates/proto",
          kind: null, req: ${JSON.stringify(requirement)} }] },
      { name: "reallyme-cose-proto", version: ${JSON.stringify(version)}, publish: null,
        dependencies: [] },
    ],
  }) };
  if (args[0] === "package") {
    const packageDir = join(${JSON.stringify(directory)}, "package");
    mkdirSync(packageDir, { recursive: true });
    writeFileSync(join(packageDir, args[2] + "-" + ${JSON.stringify(version)} + ".crate"), "reviewed bytes");
    return ok;
  }
  if (args[0] !== "publish") return { ...ok, status: 99 };
  attempts += 1;
  if (scenario === "exhausted" || (scenario === "retry" && attempts === 1)) {
    return { ...ok, status: 101, stderr: "too many requests" };
  }
  if (scenario === "failure") return { ...ok, status: 101, stderr: "package verification failed" };
  return ok;
};
syncBuiltinESMExports();
`);
    const result = spawnSync(process.execPath, ["--import", pathToFileURL(preload).href, script, mode], {
      cwd: directory,
      encoding: "utf8",
      timeout: 10_000,
      env: {
        // All child commands are mocked, so inherit no CI inputs or credentials.
        GITHUB_ACTIONS: archive === undefined ? "" : "true",
        CRATE_ARCHIVE_DIR: archive === undefined ? undefined : reviewed,
        RELEASE_VERSION: version,
      },
    });
    assert.equal(result.error, undefined);
    return { ...result, calls: JSON.parse(readFileSync(callsPath, "utf8")) };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("successful publication respects dependency order", () => {
  const result = runFixture();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[1] === "publish").map((call) => call[3]),
    ["reallyme-cose-proto", "reallyme-cose"]);
});

test("rate-limit exhaustion fails without publishing dependent crates", () => {
  const result = runFixture({ scenario: "exhausted" });
  assert.equal(result.status, 101);
  const publishes = result.calls.filter((call) => call[1] === "publish");
  assert.equal(publishes.length, 12);
  assert.ok(publishes.every((call) => call[3] === "reallyme-cose-proto"));
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 11);
});

test("transient rate limits retry before publishing dependent crates", () => {
  const result = runFixture({ scenario: "retry" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.calls.filter((call) => call[0] === "wait"), [["wait", 60000]]);
});

test("non-retryable publication errors fail immediately", () => {
  const result = runFixture({ scenario: "failure" });
  assert.equal(result.status, 101);
  assert.equal(result.calls.filter((call) => call[1] === "publish").length, 1);
  assert.equal(result.calls.filter((call) => call[0] === "wait").length, 0);
});

test("zero-major caret requirements match Cargo compatibility boundaries", () => {
  for (const [requirement, version, accepted] of [
    ["^0.0.1", "0.0.1", true],
    ["^0.0.1", "0.0.2", false],
    ["^0.2.1", "0.2.2", true],
    ["^0.2.2", "0.3.0", false],
    ["^0.2.1junk", "0.2.2", false],
  ]) {
    const result = runFixture({ mode: "order", requirement, version });
    assert.equal(result.status === 0, accepted, `${requirement} / ${version}`);
    assert.ok(result.calls.every((call) => call[1] === "metadata"));
  }
});

test("CI publishes only archives matching package preflight", () => {
  const matched = runFixture({ archive: "reviewed bytes" });
  assert.equal(matched.status, 0, matched.stderr);
  const mismatched = runFixture({ archive: "different bytes" });
  assert.equal(mismatched.status, 1);
  assert.match(mismatched.stderr, /does not match preflight/);
  assert.ok(mismatched.calls.every((call) => call[1] !== "publish"));
});

test("CI verifies the registry bytes before publishing dependent crates", () => {
  const result = runFixture({ archive: "reviewed bytes", scenario: "registry-mismatch" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /published from different source bytes/);
  assert.deepEqual(result.calls.filter((call) => call[1] === "publish").map((call) => call[3]),
    ["reallyme-cose-proto"]);
});
