#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { appendFileSync, lstatSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const MAX_COMMAND_OUTPUT_BYTES = 1_048_576;
const MAX_MANIFEST_BYTES = 65_536;
const PUBLISHABLE_MANIFESTS = Object.freeze([
  "crates/cose/Cargo.toml",
  "crates/proto/Cargo.toml",
]);

export class ReleaseSourceError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReleaseSourceError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new ReleaseSourceError(code);
};

const run = (command, arguments_, { capture = true } = {}) => {
  const result = spawnSync(command, arguments_, {
    encoding: "utf8",
    maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
    stdio: capture ? ["ignore", "pipe", "ignore"] : "inherit",
  });
  if (result.error !== undefined || result.status !== 0) {
    fail("source-command-failed");
  }
  return capture && typeof result.stdout === "string" ? result.stdout.trim() : "";
};

const readManifestVersion = (path) => {
  let status;
  let contents;
  try {
    status = lstatSync(path);
    if (status.isSymbolicLink() || !status.isFile() || status.size > MAX_MANIFEST_BYTES) {
      fail("invalid-release-manifest");
    }
    contents = readFileSync(path, "utf8");
  } catch (error) {
    if (error instanceof ReleaseSourceError) {
      throw error;
    }
    fail("invalid-release-manifest");
  }
  const versions = [...contents.matchAll(/^version = "([^"]+)"$/gmu)];
  if (versions.length !== 1 || versions[0][1] === undefined) {
    fail("invalid-release-manifest");
  }
  return versions[0][1];
};

export const verifyReleaseSource = ({ env = process.env } = {}) => {
  const releaseSha = env.RELEASE_SHA;
  const releaseVersion = env.RELEASE_VERSION;
  if (typeof releaseSha !== "string" || !FULL_SHA_PATTERN.test(releaseSha)) {
    fail("invalid-release-sha");
  }
  if (typeof releaseVersion !== "string" || !VERSION_PATTERN.test(releaseVersion)) {
    fail("invalid-release-version");
  }
  if (env.GITHUB_SHA !== undefined && env.GITHUB_SHA !== releaseSha) {
    fail("workflow-head-mismatch");
  }
  if (run("git", ["rev-parse", "HEAD"]) !== releaseSha) {
    fail("checkout-mismatch");
  }
  run(
    "git",
    ["fetch", "--force", "--no-tags", "origin", "main:refs/remotes/origin/main"],
    { capture: false },
  );
  if (run("git", ["rev-parse", "refs/remotes/origin/main"]) !== releaseSha) {
    fail("origin-main-mismatch");
  }
  for (const manifest of PUBLISHABLE_MANIFESTS) {
    if (readManifestVersion(manifest) !== releaseVersion) {
      fail("manifest-version-mismatch");
    }
  }
  return { releaseSha, releaseVersion };
};

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    const identity = verifyReleaseSource();
    if (process.env.RELEASE_SOURCE_WRITE_GITHUB_OUTPUT === "1") {
      const outputPath = process.env.GITHUB_OUTPUT;
      if (typeof outputPath !== "string" || outputPath.length === 0) {
        fail("missing-github-output");
      }
      appendFileSync(
        outputPath,
        `release_sha=${identity.releaseSha}\nrelease_version=${identity.releaseVersion}\n`,
        { encoding: "utf8" },
      );
    }
    console.log("release source matches the workflow head, current main, and crate manifests");
  } catch (error) {
    const code = error instanceof ReleaseSourceError ? error.code : "unexpected-failure";
    console.error(`release source verification failed: ${code}`);
    process.exit(1);
  }
}
