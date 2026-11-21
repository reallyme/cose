#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const upstream = "github:reallyme/release-readiness#16aab5287de498e858ff3b85d9e66d7c9f7ebb74";
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
