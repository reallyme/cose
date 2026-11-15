#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const upstream = "github:reallyme/release-readiness#7dffa0366a43fe9cc7b98a8040d37dd701d7955e";
const result = spawnSync("npm", [
  "exec", "--yes", `--package=${upstream}`, "--", "reallyme-release-readiness",
  ...process.argv.slice(2),
], {
  cwd: fileURLToPath(new URL("../", import.meta.url)),
  env: { ...process.env, RELEASE_READINESS_PUBLIC_REPO: "true" },
  stdio: "inherit",
});
if (!Number.isInteger(result.status)) {
  console.error("The pinned Release Readiness runner did not complete.");
  process.exitCode = 1;
} else {
  process.exitCode = result.status;
}
