// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import { collectOperationContractRoutingViolations } from "./operation-contract-routing.mjs";

const repositoryRoot = fileURLToPath(new URL("../..", import.meta.url));

function repositoryReader(path) {
  return readFileSync(resolve(repositoryRoot, path), "utf8");
}

function violationsAfter(path, mutate) {
  return collectOperationContractRoutingViolations((requestedPath) => {
    const source = repositoryReader(requestedPath);
    return requestedPath === path ? mutate(source) : source;
  });
}

function replaceOnce(source, before, after) {
  assert.equal(source.split(before).length - 1, 1, `fixture must contain ${before} exactly once`);
  return source.replace(before, after);
}

test("current operation contract satisfies every routing invariant", () => {
  assert.deepEqual(collectOperationContractRoutingViolations(repositoryReader), []);
});

test("a missing operation-contract route cannot hide behind another dispatcher branch", () => {
  const violations = violationsAfter("crates/cose/src/operation_contract/execute.rs", (source) =>
    replaceOnce(
      source,
      "super::key::parse::result(*request)",
      "super::key::convert::to_public_bytes_result(*request)",
    ),
  );
  assert.match(violations.join("\n"), /KeyParse must call .*key::parse::result exactly once; found 0/u);
});

test("adapter comments cannot impersonate an executable semantic call", () => {
  const violations = violationsAfter("crates/cose/src/operation_contract/key/parse.rs", (source) =>
    replaceOnce(
      source,
      "parse_cose_key(CoseKeyParseInput::new(&encoded_key))",
      "bypass_parse(CoseKeyParseInput::new(&encoded_key)) // parse_cose_key(CoseKeyParseInput::new(&encoded_key))",
    ),
  );
  assert.match(violations.join("\n"), /key\/parse\.rs result must call parse_cose_key exactly 1 time.*found 0/u);
});

test("duplicate semantic execution is rejected", () => {
  const violations = violationsAfter("crates/cose/src/operation_contract/sign1/create.rs", (source) =>
    replaceOnce(
      source,
      "let result = create_cose_sign1(",
      "let _duplicate = create_cose_sign1(\n    let result = create_cose_sign1(",
    ),
  );
  assert.match(violations.join("\n"), /attached_result must call create_cose_sign1 exactly 1 time/u);
});

test("native convenience APIs cannot bypass their semantic facade", () => {
  const violations = violationsAfter("crates/cose/src/encrypt/create.rs", (source) =>
    replaceOnce(
      source,
      "cose_encrypt_ml_kem_direct_with_external_aad(request, &[])",
      "encrypt_ml_kem(request, CoseMlKemMode::Direct, &[])",
    ),
  );
  assert.match(
    violations.join("\n"),
    /cose_encrypt_ml_kem_direct must call cose_encrypt_ml_kem_direct_with_external_aad/u,
  );
  assert.match(violations.join("\n"), /cose_encrypt_ml_kem_direct must call encrypt_ml_kem exactly 0 time.*found 1/u);
});

test("shared encryption adapters must invoke the selected operation exactly once", () => {
  const violations = violationsAfter("crates/cose/src/operation_contract/encrypt/create.rs", (source) =>
    replaceOnce(source, "let output = operation(input)", "let output = bypass(input)"),
  );
  assert.match(violations.join("\n"), /encrypt_result must call operation exactly 1 time.*found 0/u);
});

test("adapters cannot introduce independent error classification", () => {
  const violations = violationsAfter("crates/cose/src/operation_contract/encrypt/decrypt.rs", (source) =>
    replaceOnce(
      source,
      "pub(crate) fn result(",
      "const _: Option<CoseWireError> = Some(CoseWireError::backend_internal);\n\npub(crate) fn result(",
    ),
  );
  assert.match(violations.join("\n"), /encrypt\/decrypt\.rs must not contain CoseWireError constructors/u);
});
