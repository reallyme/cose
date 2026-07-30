#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { createHash, timingSafeEqual } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const RELEASE_READINESS_COMMIT = "44065b7488a8d3c77f66f530dff770fb39be9707";
const RELEASE_READINESS_CORE_SHA256 =
  "fcc0b725a85784617568c29f1aa3382a206faaddc3a22012e46f0e35303e4e6d";
const RELEASE_READINESS_CORE_URL =
  `https://raw.githubusercontent.com/reallyme/release-readiness/${RELEASE_READINESS_COMMIT}/core.mjs`;
const VENDORED_CORE_PATH = "scripts/release-readiness/core.mjs";
const LOCAL_CHECKER_PATH = "scripts/check_release_readiness.mjs";
const MAX_CORE_BYTES = 262_144;
const FETCH_TIMEOUT_MILLISECONDS = 30_000;

const fail = (reason) => {
  console.error(`pinned release readiness failed: ${reason}`);
  process.exit(1);
};

const sha256 = (value) => createHash("sha256").update(value).digest();

const expectedDigest = Buffer.from(RELEASE_READINESS_CORE_SHA256, "hex");
if (expectedDigest.length !== 32) {
  fail("configured core digest is invalid");
}

let localCore;
try {
  const checkerStatus = lstatSync(LOCAL_CHECKER_PATH);
  if (checkerStatus.isSymbolicLink() || !checkerStatus.isFile()) {
    fail("local checker must be a regular file");
  }
  const status = lstatSync(VENDORED_CORE_PATH);
  if (status.isSymbolicLink() || !status.isFile()) {
    fail("vendored core must be a regular file");
  }
  if (status.size === 0 || status.size > MAX_CORE_BYTES) {
    fail("vendored core size is outside the accepted boundary");
  }
  localCore = readFileSync(VENDORED_CORE_PATH);
} catch {
  fail("vendored core is missing or inaccessible");
}
if (!timingSafeEqual(sha256(localCore), expectedDigest)) {
  fail("vendored core does not match the reviewed upstream pin");
}

let response;
try {
  response = await fetch(RELEASE_READINESS_CORE_URL, {
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MILLISECONDS),
  });
} catch {
  fail("pinned upstream core could not be fetched");
}
if (!response.ok || response.body === null) {
  fail("pinned upstream core returned an invalid response");
}

const contentLength = response.headers.get("content-length");
if (contentLength !== null) {
  if (!/^[1-9][0-9]*$/u.test(contentLength)) {
    fail("pinned upstream core returned an invalid content length");
  }
  const parsedLength = Number.parseInt(contentLength, 10);
  if (!Number.isSafeInteger(parsedLength) || parsedLength <= 0 || parsedLength > MAX_CORE_BYTES) {
    fail("pinned upstream core length is outside the accepted boundary");
  }
}

const reader = response.body.getReader();
const chunks = [];
let totalLength = 0;
for (;;) {
  let result;
  try {
    result = await reader.read();
  } catch {
    fail("pinned upstream core response could not be read");
  }
  if (result.done) {
    break;
  }
  const chunk = result.value;
  if (!(chunk instanceof Uint8Array) || chunk.length > MAX_CORE_BYTES - totalLength) {
    fail("pinned upstream core exceeds the accepted boundary");
  }
  chunks.push(chunk);
  totalLength += chunk.length;
}
if (totalLength === 0) {
  fail("pinned upstream core is empty");
}
const upstreamCore = Buffer.concat(chunks, totalLength);
if (!timingSafeEqual(sha256(upstreamCore), expectedDigest)) {
  fail("pinned upstream core digest does not match the reviewed commit");
}

const checker = spawnSync(process.execPath, [LOCAL_CHECKER_PATH, ...process.argv.slice(2)], {
  env: process.env,
  stdio: "inherit",
});
if (checker.error !== undefined) {
  fail("local release readiness checker could not be started");
}
if (!Number.isInteger(checker.status)) {
  fail("local release readiness checker ended without a deterministic status");
}
process.exit(checker.status);
