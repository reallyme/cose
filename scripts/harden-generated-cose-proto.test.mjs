// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = fileURLToPath(new URL("..", import.meta.url));
const generated = "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs";
const view = "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.__view.rs";
const oneof = "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.__oneof.rs";
const script = "scripts/harden-generated-cose-proto.mjs";

function withFixture(callback) {
  const directory = mkdtempSync(join(tmpdir(), "cose-hardening-test-"));
  try {
    for (const file of [script, generated, view, oneof, "crates/proto/proto/reallyme/cose/v1/cose.proto"]) {
      mkdirSync(dirname(join(directory, file)), { recursive: true });
      cpSync(join(root, file), join(directory, file));
    }
    callback(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function run(directory, args) {
  const result = spawnSync(process.execPath, [join(directory, script), ...args], {
    cwd: directory, encoding: "utf8", timeout: 10_000,
  });
  assert.equal(result.error, undefined);
  return result;
}

test("idempotence check leaves valid generated files unchanged", () => {
  withFixture((directory) => {
    const before = [generated, view, oneof].map((file) => readFileSync(join(directory, file)));
    const result = run(directory, ["--check-idempotent"]);
    assert.equal(result.status, 0, result.stderr);
    [generated, view, oneof].forEach((file, index) =>
      assert.deepEqual(readFileSync(join(directory, file)), before[index]));
  });
});

test("failed idempotence checks do not repair their input", () => {
  withFixture((directory) => {
    const file = join(directory, generated);
    const original = readFileSync(file, "utf8");
    const weakened = original.replace('.field("payload", &"<redacted>")', '.field("payload", &self.payload)');
    assert.notEqual(weakened, original);
    writeFileSync(file, weakened);
    assert.equal(run(directory, ["--check-idempotent"]).status, 1);
    assert.equal(readFileSync(file, "utf8"), weakened);
    assert.equal(run(directory, []).status, 0);
    assert.equal(readFileSync(file, "utf8"), original);
  });
});

test("a malformed companion file prevents partial hardening writes", () => {
  withFixture((directory) => {
    const file = join(directory, generated);
    const weakened = readFileSync(file, "utf8").replace('.field("payload", &"<redacted>")', '.field("payload", &self.payload)');
    writeFileSync(file, weakened);
    writeFileSync(join(directory, oneof), "invalid generated oneof\n");
    assert.equal(run(directory, []).status, 1);
    assert.equal(readFileSync(file, "utf8"), weakened);
  });
});
