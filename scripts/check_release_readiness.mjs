#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const expectedPackageName = "reallyme-cose";
const expectedVersion = "0.1.2";
const packageListArgs =
  process.env.GITHUB_ACTIONS === "true"
    ? ["package", "--list", "-p", expectedPackageName]
    : ["package", "--list", "-p", expectedPackageName, "--allow-dirty"];
const requiredRegistryDeps = new Map([
  ["reallyme-codec", "0.1.1"],
  ["reallyme-crypto", "0.1.6"],
]);

function fail(message) {
  console.error(`release readiness check failed: ${message}`);
  process.exit(1);
}

function readText(path) {
  return readFileSync(resolve(root, path), "utf8");
}

function assertContains(path, needle) {
  if (!readText(path).includes(needle)) {
    fail(`${path} does not contain ${needle}`);
  }
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
    env: options.env ?? process.env,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    if (options.capture) {
      process.stdout.write(result.stdout);
      process.stderr.write(result.stderr);
    }
    process.exit(result.status ?? 1);
  }
  return result;
}

const cargoToml = readText("Cargo.toml");
assertContains("Cargo.toml", `name = "${expectedPackageName}"`);
assertContains("Cargo.toml", `version = "${expectedVersion}"`);
assertContains("Cargo.toml", "publish = true");
assertContains("Cargo.toml", 'repository = "https://github.com/reallyme/cose"');
assertContains("Cargo.toml", 'include = [');
assertContains("Cargo.toml", '"/src/**/*.rs"');
assertContains("Cargo.toml", '"/tests/**/*.rs"');
assertContains("Cargo.toml", '"/conformance/**/*.json"');
assertContains("Cargo.toml", '"/proto/**/*.proto"');
assertContains("Cargo.toml", '"/buf.yaml"');
assertContains("Cargo.toml", '"/README.md"');
assertContains("Cargo.toml", '"/LICENSE"');
assertContains("Cargo.toml", '"/NOTICE"');
assertContains("README.md", "actions/workflows/rust-ci.yml/badge.svg");
assertContains("README.md", "crates.io/crates/reallyme-cose");
assertContains("README.md", "Unsupported COSE Surface");
assertContains("README.md", "Resource Limits");
assertContains("README.md", "Independent Vector Audit");
assertContains("conformance/vectors/manifest.json", "reallyme.cose.conformance.vector_manifest.v1");
assertContains("tools/vector-audit/Cargo.toml", 'name = "reallyme-cose-vector-audit"');
assertContains("buf.yaml", "modules:");
assertContains("buf.yaml", "- path: proto");
assertContains("proto/reallyme/cose/v1/cose.proto", "package reallyme.cose.v1;");
assertContains("proto/reallyme/cose/v1/cose.proto", "message CoseError");
assertContains("proto/reallyme/cose/v1/cose.proto", "message CoseSign1Error");
assertContains("proto/reallyme/cose/v1/cose.proto", "message CoseKeyError");
assertContains("proto/reallyme/cose/v1/cose.proto", "message CoseMultikeyError");
assertContains("proto/reallyme/cose/v1/cose.proto", "enum CoseErrorReason");
assertContains(
  "proto/reallyme/cose/v1/cose.proto",
  "COSE_ERROR_REASON_COMMON_CBOR = 100;",
);
assertContains(
  "proto/reallyme/cose/v1/cose.proto",
  "COSE_ERROR_REASON_SIGN1_MISSING_PAYLOAD = 200;",
);
assertContains(
  "proto/reallyme/cose/v1/cose.proto",
  "COSE_ERROR_REASON_KEY_MISSING_KEY_MATERIAL = 300;",
);
assertContains(
  "proto/reallyme/cose/v1/cose.proto",
  "COSE_ERROR_REASON_MULTIKEY_INVALID_MULTIKEY = 400;",
);
assertContains(".github/workflows/rust-ci.yml", "paths-ignore:");
assertContains(".github/workflows/fuzz.yml", "paths-ignore:");
assertContains(".github/workflows/crates-release.yml", "CARGO_REGISTRY_TOKEN");

for (const [crateName, version] of requiredRegistryDeps) {
  const dependencyLine = `${crateName} = { version = "${version}", default-features = false`;
  if (!cargoToml.includes(dependencyLine)) {
    fail(`${crateName} must use crates.io version ${version} with default-features disabled`);
  }
}

const metadataResult = run("cargo", ["metadata", "--format-version", "1", "--no-deps"], {
  capture: true,
});
const metadata = JSON.parse(metadataResult.stdout);
const rootPackage = metadata.packages.find((pkg) => pkg.name === expectedPackageName);
if (!rootPackage) {
  fail(`cargo metadata did not expose ${expectedPackageName}`);
}
if (rootPackage.version !== expectedVersion) {
  fail(`${expectedPackageName} metadata version is ${rootPackage.version}`);
}

for (const [crateName, version] of requiredRegistryDeps) {
  const dep = rootPackage.dependencies.find((candidate) => candidate.name === crateName);
  if (!dep) {
    fail(`${expectedPackageName} is missing ${crateName}`);
  }
  if (dep.req !== `^${version}`) {
    fail(`${crateName} dependency requirement is ${dep.req}, expected ^${version}`);
  }
  if (typeof dep.source !== "string" || !dep.source.startsWith("registry+")) {
    fail(`${crateName} must resolve from crates.io, not a path or git dependency`);
  }
}

const validationCommands = [
  ["cargo", ["fmt", "--check"]],
  ["cargo", ["check", "--workspace", "--all-features"]],
  ["cargo", ["check", "--workspace", "--all-features"], { env: { ...process.env, RUSTFLAGS: "-Dwarnings" } }],
  [
    "cargo",
    ["check", "--workspace", "--no-default-features"],
    { env: { ...process.env, RUSTFLAGS: "-Dwarnings" } },
  ],
  ["cargo", ["clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"]],
  ["cargo", ["fmt", "--manifest-path", "tools/vector-audit/Cargo.toml", "--check"]],
  ["cargo", ["clippy", "--manifest-path", "tools/vector-audit/Cargo.toml", "--all-targets", "--", "-D", "warnings"]],
  ["cargo", ["test", "--workspace", "--all-features"]],
  ["cargo", ["run", "--manifest-path", "tools/vector-audit/Cargo.toml", "--", "."]],
  ["cargo", ["check", "--workspace", "--no-default-features", "--features", "native"]],
  [
    "cargo",
    [
      "check",
      "--workspace",
      "--target",
      "wasm32-unknown-unknown",
      "--no-default-features",
      "--features",
      "wasm",
    ],
  ],
  ["cargo", ["deny", "check", "bans", "licenses", "sources"]],
  ["cargo", packageListArgs],
];

for (const [command, args, options] of validationCommands) {
  run(command, args, options);
}

console.log(`${expectedPackageName} ${expectedVersion} release readiness checks passed`);
