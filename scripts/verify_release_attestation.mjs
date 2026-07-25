#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { appendFileSync, lstatSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const FULL_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/u;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const PREFLIGHT_WORKFLOW = "crates-package-preflight.yml";
const PREFLIGHT_PATH = `.github/workflows/${PREFLIGHT_WORKFLOW}@refs/heads/main`;
const ATTESTATION_SCHEMA = "reallyme.cose.crates_preflight.v1";
const DEFAULT_ATTESTATION_PATH = "release-attestation/crates-preflight.json";
const MAX_COMMAND_OUTPUT_BYTES = 1_048_576;
const MAX_ATTESTATION_BYTES = 16_384;
const ATTESTATION_KEYS = Object.freeze([
  "release_sha",
  "repository",
  "run_attempt",
  "run_id",
  "schema",
  "version",
  "workflow",
]);

export class ReleaseAttestationError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReleaseAttestationError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new ReleaseAttestationError(code);
};

const parsePositiveInteger = (value, code) => {
  if (typeof value !== "string" || !POSITIVE_INTEGER_PATTERN.test(value)) {
    fail(code);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    fail(code);
  }
  return parsed;
};

const runJson = (arguments_, code) => {
  const result = spawnSync("gh", arguments_, {
    encoding: "utf8",
    maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.error !== undefined || result.status !== 0 || typeof result.stdout !== "string") {
    fail(code);
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    fail(code);
  }
};

const readAttestation = (path) => {
  let status;
  let contents;
  try {
    status = lstatSync(path);
    if (
      status.isSymbolicLink() ||
      !status.isFile() ||
      status.size === 0 ||
      status.size > MAX_ATTESTATION_BYTES
    ) {
      fail("invalid-attestation-file");
    }
    contents = readFileSync(path, "utf8");
  } catch (error) {
    if (error instanceof ReleaseAttestationError) {
      throw error;
    }
    fail("invalid-attestation-file");
  }
  try {
    return JSON.parse(contents);
  } catch {
    fail("invalid-attestation-json");
  }
};

const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

export const verifyAttestationDocument = (value, expected) => {
  if (!isRecord(value)) {
    fail("invalid-attestation-document");
  }
  const keys = Object.keys(value).sort();
  if (keys.length !== ATTESTATION_KEYS.length || keys.some((key, index) => key !== ATTESTATION_KEYS[index])) {
    fail("invalid-attestation-document");
  }
  if (
    value.schema !== ATTESTATION_SCHEMA ||
    value.repository !== expected.repository ||
    value.workflow !== PREFLIGHT_WORKFLOW ||
    value.run_id !== expected.runId ||
    value.run_attempt !== 1 ||
    value.release_sha !== expected.releaseSha ||
    value.version !== expected.releaseVersion
  ) {
    fail("attestation-input-mismatch");
  }
};

export const verifyWorkflowRun = (value, expected) => {
  if (!isRecord(value)) {
    fail("invalid-preflight-run");
  }
  if (
    value.workflow_id !== expected.workflowId ||
    value.id !== expected.runId ||
    value.event !== "workflow_dispatch" ||
    value.head_branch !== "main" ||
    value.head_sha !== expected.releaseSha ||
    value.status !== "completed" ||
    value.conclusion !== "success" ||
    value.run_attempt !== 1 ||
    value.path !== PREFLIGHT_PATH
  ) {
    fail("preflight-run-mismatch");
  }
};

export const verifyReleaseAttestation = ({ env = process.env } = {}) => {
  const repository = env.GITHUB_REPOSITORY;
  const releaseSha = env.RELEASE_SHA;
  const releaseVersion = env.RELEASE_VERSION;
  if (typeof repository !== "string" || !REPOSITORY_PATTERN.test(repository)) {
    fail("invalid-repository");
  }
  if (typeof releaseSha !== "string" || !FULL_SHA_PATTERN.test(releaseSha)) {
    fail("invalid-release-sha");
  }
  if (typeof releaseVersion !== "string" || !VERSION_PATTERN.test(releaseVersion)) {
    fail("invalid-release-version");
  }
  if (typeof env.GH_TOKEN !== "string" || env.GH_TOKEN.length === 0) {
    fail("missing-github-token");
  }
  if (env.GITHUB_SHA !== releaseSha) {
    fail("workflow-head-mismatch");
  }
  const runId = parsePositiveInteger(env.PREFLIGHT_RUN_ID, "invalid-preflight-run-id");
  const workflow = runJson(
    ["api", `repos/${repository}/actions/workflows/${PREFLIGHT_WORKFLOW}`],
    "workflow-query-failed",
  );
  if (!isRecord(workflow) || !Number.isSafeInteger(workflow.id) || workflow.id < 1) {
    fail("invalid-workflow-response");
  }
  const run = runJson(
    ["api", `repos/${repository}/actions/runs/${runId}`],
    "preflight-run-query-failed",
  );
  verifyWorkflowRun(run, { workflowId: workflow.id, runId, releaseSha });
  const mainRef = runJson(
    ["api", `repos/${repository}/git/ref/heads/main`],
    "main-ref-query-failed",
  );
  if (!isRecord(mainRef) || !isRecord(mainRef.object) || mainRef.object.sha !== releaseSha) {
    fail("release-sha-is-not-current-main");
  }
  const attestationPath = env.RELEASE_ATTESTATION_PATH ?? DEFAULT_ATTESTATION_PATH;
  if (typeof attestationPath !== "string" || attestationPath.length === 0) {
    fail("invalid-attestation-path");
  }
  verifyAttestationDocument(readAttestation(attestationPath), {
    repository,
    runId,
    releaseSha,
    releaseVersion,
  });
  return { releaseSha, releaseVersion, runId };
};

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    const attestation = verifyReleaseAttestation();
    if (process.env.RELEASE_ATTESTATION_WRITE_GITHUB_OUTPUT === "1") {
      const outputPath = process.env.GITHUB_OUTPUT;
      if (typeof outputPath !== "string" || outputPath.length === 0) {
        fail("missing-github-output");
      }
      appendFileSync(
        outputPath,
        `release_sha=${attestation.releaseSha}\nrelease_version=${attestation.releaseVersion}\n`,
        { encoding: "utf8" },
      );
    }
    console.log("reviewed crates package preflight attestation verified");
  } catch (error) {
    const code = error instanceof ReleaseAttestationError ? error.code : "unexpected-failure";
    console.error(`release attestation verification failed: ${code}`);
    process.exit(1);
  }
}
