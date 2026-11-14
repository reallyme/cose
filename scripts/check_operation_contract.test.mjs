// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { assertCompleteOperationContract } from "./check_operation_contract.mjs";
import { schemaScalarClassifications } from "./schema_contract.mjs";
import { rustFunctionBody } from "./release-readiness/operation-contract-routing.mjs";

const files = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" }).split("\0").filter(Boolean);
const source = new Map(files.filter((path) => /\.(?:rs|proto)$/u.test(path)).map((path) => [path, readFileSync(path, "utf8")]));
function check(changes = new Map()) {
  assertCompleteOperationContract({
    readText: (path) => changes.get(path) ?? source.get(path) ?? readFileSync(path, "utf8"),
    loadTrackedFiles: () => [...new Set([...files, ...changes.keys()])],
    fail: (message) => assert.fail(message),
  });
}

test("the complete schema represents the retained public operation adapters", () => check());
test("a new public operation cannot bypass protobuf", () => {
  assert.throws(() => check(new Map([["crates/cose/src/new_operation.rs", "pub fn new_operation() {}\n"]])), /needs a protobuf contract/u);
});
test("nested and qualified public functions cannot bypass the operation inventory",()=>{
  for(const code of ["pub mod nested { pub fn another_operation() {} }", "pub const fn another_operation() {}", "pub async fn another_operation() {}", "// pub fn documented_only() {}\npub fn another_operation() {}"]){
    assert.throws(()=>check(new Map([["crates/cose/src/new_operation.rs",code]])),/needs a protobuf contract/u);
  }
  for(const path of ["crates/cose/src/api.rs","crates/cose/src/wire.rs","crates/cose/src/operation_contract/providers.rs"]){
    assert.throws(()=>check(new Map([[path,source.get(path)+"\npub fn another_operation() {}\n"]])),/needs a protobuf contract/u);
  }
});
test("a new result cannot silently reuse a different request identifier", () => {
  const path = "crates/proto/proto/reallyme/cose/v1/cose.proto";
  const original = source.get(path);
  assert.equal(typeof original, "string");
  assert.throws(() => check(new Map([[path, original.replace("CoseMac0VerifyResult mac0_verify_detached = 4000;", "CoseMac0VerifyResult mac0_verify_detached = 4001;")]])), /identity differs/u);
});
test("dispatch names in comments do not satisfy an executable route", () => {
  const path = "crates/cose/src/operation_contract/execute.rs";
  const original = source.get(path);
  assert.equal(typeof original, "string");
  assert.throws(() => check(new Map([[path, original.replace("Operation::Mac0VerifyDetached(request)", "Operation::Missing(request) /* Operation::Mac0VerifyDetached(request) */")]])), /exactly one dispatch arm/u);
});
test("fixed-size arrays are accepted without accepting bodyless declarations", () => {
  assert.equal(rustFunctionBody("pub fn key(context: [u8; 32]) -> [u8; 32] { context }", "key"), " context ");
  assert.equal(rustFunctionBody("fn key(context: [u8; 32]); fn other() {}", "key"), null);
});
test("new identifying scalar fields require a schema ownership classification", () => {
  assert.throws(() => schemaScalarClassifications("message Key {\n bytes key = 1;\n}\n"), /ownership classification missing/u);
  assert.deepEqual(schemaScalarClassifications("message Key {\n // SENSITIVE: protected material.\n bytes key = 1;\n}\n"), [{ message: "Key", field: "key", kind: "bytes", sensitivity: "sensitive" }]);
});
