// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {cpSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname,join,resolve} from "node:path";
import test from "node:test";
import {checkFreshness,generate,generatedPaths,filesUnder} from "./generate_cose_contract.mjs";
import {sanitizeEnumDiagnostics} from "./sanitize_enum_diagnostics.mjs";

function fixture(callback) {
  const root=mkdtempSync(join(tmpdir(),"cose-generation-test-"));
  try {
    for(const path of ["buf.yaml","buf.gen.yaml","rust-toolchain.toml","crates/proto/proto"]) {
      mkdirSync(dirname(join(root,path)),{recursive:true});
      cpSync(path,join(root,path),{recursive:true});
    }
    callback(root);
  } finally {rmSync(root,{recursive:true,force:true});}
}
function snapshot(root) {
  return generatedPaths.flatMap(path=>path.endsWith(".rs")?[path]:filesUnder(root,path))
    .map(path=>[path,readFileSync(join(root,path),"utf8")]);
}

test("native generation is repeatable and freshness cannot repair its evidence",()=>fixture(root=>{
  generate(root);
  const first=snapshot(root);
  generate(root);
  assert.deepEqual(snapshot(root),first);
  assert.doesNotThrow(()=>checkFreshness(root));
  const path="crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs";
  const changed=readFileSync(join(root,path),"utf8")+"\n// stale output\n";
  writeFileSync(join(root,path),changed);
  assert.throws(()=>checkFreshness(root),/stale generated contract/u);
  assert.equal(readFileSync(join(root,path),"utf8"),changed);
}));

test("native selectors fail closed for incomplete cleanup and shadowed JSON policy",()=>fixture(root=>{
  const config=readFileSync(join(root,"buf.gen.yaml"),"utf8");
  for(const changed of [
    config.replace("unknown_fields=false","unknown_fields=true"),
    config.replace("zeroize_in=.reallyme.cose.v1","zeroize_in=.reallyme.cose.missing"),
    config.replace("json_policy_type=crate::SecretBytes","json_policy_type=other::SecretBytes"),
  ]) {
    writeFileSync(join(root,"buf.gen.yaml"),changed);
    assert.throws(()=>generate(root),/generation command failed/u);
  }
}));

test("a wrong generator version fails before writing output",()=>fixture(root=>{
  const bin=join(root,"bin");mkdirSync(bin);
  writeFileSync(join(bin,"protoc-gen-reallyme-buffa"),'#!/bin/sh\nprintf "%s\\n" "protoc-gen-reallyme-buffa 0.9.2"\n',{mode:0o755});
  const result=spawnSync(process.execPath,[resolve("scripts/generate_cose_contract.mjs")],{
    cwd:root,encoding:"utf8",env:{...process.env,PATH:`${bin}:${process.env.PATH}`},
  });
  assert.notEqual(result.status,0);
  assert.match(result.stderr,/unsupported generator name or version/u);
  assert.deepEqual(filesUnder(root,"crates/proto/src/generated"),[]);
}));

test("temporary standalone enum diagnostics preserve fixed errors and reject drift",()=>{
  const source='::serde::de::Error::custom( ::buffa::alloc::format!("enum value {v} out of i32 range"), )\n'
    +'::serde::de::Error::custom( ::buffa::alloc::format!("unknown enum value {v32}"), )';
  const output=sanitizeEnumDiagnostics(source);
  assert.match(output,/custom\("enum value out of i32 range"\)/u);
  assert.match(output,/custom\("unknown enum value"\)/u);
  assert.doesNotMatch(output,/format!|\{v/u);
  assert.throws(()=>sanitizeEnumDiagnostics(output),/differs from the published generator/u);
  assert.throws(()=>sanitizeEnumDiagnostics(source+'\n::buffa::alloc::format!("other {v}")'),/differs from the published generator/u);
});
