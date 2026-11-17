// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import { collectOperationContractRoutingViolations, maskRustNonCode, rustFunctionBody } from "./operation-contract-routing.mjs";

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
      "super::key::parse::result(core::mem::take(&mut **request))",
      "super::key::convert::to_public_bytes_result(core::mem::take(&mut **request))",
    ),
  );
  assert.match(violations.join("\n"), /KeyParse must call .*key::parse::result exactly once; found 0/u);
});

test("swapped dispatcher adapters are rejected even when both calls remain present", () => {
  const violations = violationsAfter("crates/cose/src/operation_contract/execute.rs", (source) =>
    source
      .replace(
        "super::sign1::create::attached_result(core::mem::take(&mut **request))",
        "__SWAPPED_ATTACHED_ADAPTER__",
      )
      .replace(
        "super::sign1::create::detached_result(core::mem::take(&mut **request))",
        "super::sign1::create::attached_result(core::mem::take(&mut **request))",
      )
      .replace("__SWAPPED_ATTACHED_ADAPTER__", "super::sign1::create::detached_result(core::mem::take(&mut **request))"),
  );
  assert.match(violations.join("\n"), /Sign1Create must invoke .*attached_result in its own match arm/u);
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

test("historical Sign1 names must delegate to exact-registration facades", () => {
  const path = "crates/cose/src/sign1/verify.rs";
  for (const [entrypoint, facade, semantic] of [
    ["cose_verify1_with_policy_and_external_aad", "cose_verify1_with_exact_algorithm", "verify_cose_sign1"],
    ["cose_verify1_detached_with_policy_and_external_aad", "cose_verify1_detached_with_exact_algorithm", "verify_detached_cose_sign1"],
  ]) {
    const violations = violationsAfter(path, (source) => {
      const body = rustFunctionBody(source, entrypoint);
      assert.notEqual(body, null);
      const start = source.indexOf(body);
      assert.notEqual(start, -1);
      const replacement = replaceOnce(body, `${facade}(`, `${semantic}(`);
      return source.slice(0, start) + replacement + source.slice(start + body.length);
    });
    assert.ok(violations.some((message) => message.includes(`${entrypoint} must call ${facade} exactly 1`)));
    assert.ok(violations.some((message) => message.includes(`${entrypoint} must call ${semantic} exactly 0`)));
  }
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

test("non-BMP comments and literals preserve executable offsets", () => {
  const source = '// 🔒 nested marker\nfn route() { let label = "🔑"; /* 🦀 */ execute(); }';
  const masked = maskRustNonCode(source);
  assert.equal(masked.length, source.length);
  assert.equal(masked.indexOf("fn route"), source.indexOf("fn route"));
  assert.equal(masked.indexOf("execute();"), source.indexOf("execute();"));
  assert.match(rustFunctionBody(source, "route"), /execute\(\);/u);
});

test("non-BMP comments cannot conceal a forbidden facade call", () => {
  const violations = violationsAfter("crates/cose/src/operation_contract/key/parse.rs", (source) =>
    replaceOnce(source, "parse_cose_key(CoseKeyParseInput::new(&encoded_key))",
      'cose_key_from_slice(&encoded_key) // 🔒 parse_cose_key(CoseKeyParseInput::new(&encoded_key))'),
  );
  assert.match(violations.join("\n"), /must not call native facade cose_key_from_slice/u);
  assert.match(violations.join("\n"), /must call parse_cose_key exactly 1 time.*found 0/u);
});
