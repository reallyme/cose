#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const wasmTarget = "wasm32-unknown-unknown";
const cargoArgs = [
  "check",
  "--workspace",
  "--target",
  wasmTarget,
  "--no-default-features",
  "--features",
  "wasm",
];

function run(command, args, options = {}) {
  return spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
  });
}

const installedTargets = run("rustup", ["target", "list", "--installed"], { capture: true });
if (installedTargets.error) {
  console.error("failed to inspect installed Rust targets");
  console.error("run: rustup target add wasm32-unknown-unknown");
  process.exit(1);
}

if (!installedTargets.stdout.split(/\r?\n/u).includes(wasmTarget)) {
  console.error(`missing Rust target: ${wasmTarget}`);
  console.error(`run: rustup target add ${wasmTarget}`);
  process.exit(1);
}

console.error(`running wasm lane: cargo ${cargoArgs.join(" ")}`);
const result = run("cargo", cargoArgs);
if (result.error) {
  console.error("failed to run cargo");
  process.exit(1);
}
process.exit(result.status ?? 1);
