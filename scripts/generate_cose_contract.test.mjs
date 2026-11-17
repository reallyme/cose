// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {cpSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {dirname,join,resolve} from "node:path";
import test from "node:test";
import {checkFreshness,generate,generatedPaths,filesUnder} from "./generate_cose_contract.mjs";
import {nativeAdapterBindings} from "./native_adapter_bindings.mjs";

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

test("Buffa alone emits every native enum, with formatting as the only transformation",()=>fixture(root=>{
  const result=spawnSync("buf",["generate","--path","crates/proto/proto/reallyme"],{cwd:root,encoding:"utf8"});
  assert.equal(result.status,0,result.stderr);
  const schema=readFileSync(join(root,"crates/proto/proto/reallyme/cose/v1/cose.proto"),"utf8");
  const bindings=nativeAdapterBindings(schema);
  assert.equal(bindings.length,24);
  const paths=bindings.map(value=>join(root,"crates/proto/src/generated/buffa",value.file));
  const formatted=spawnSync("rustfmt",["--edition","2021","--config","skip_children=true",...paths],{encoding:"utf8"});
  assert.equal(formatted.status,0,formatted.stderr);
  const original=paths.map(path=>readFileSync(path));
  generate(root);
  for(const [index,adapter] of bindings.entries()) {
    assert.deepEqual(readFileSync(join(root,"crates/cose/src/generated_contract",adapter.file)),original[index]);
  }
}));

test("Buffa rejects incomplete selectors and borrowed callbacks before replacing output",()=>fixture(root=>{
  generate(root);
  const original=snapshot(root);
  const path=join(root,"crates/proto/proto/reallyme/cose/v1/cose.proto");
  const schema=readFileSync(path,"utf8");
  for(const changed of [
    schema.replace("COSE_SIGNATURE_ALGORITHM_ES384 = 212;","COSE_SIGNATURE_ALGORITHM_ES384 = 212;\n  COSE_SIGNATURE_ALGORITHM_ANOTHER = 299;"),
    schema.replace("COSE_CONTENT_MODE_DETACHED = 2;","COSE_CONTENT_MODE_DETACHED = 2;\n  COSE_CONTENT_MODE_ANOTHER = 3;"),
    schema.replace("CoseEcdsaPrehash ecdsa_prehash = 2;","CoseEcdsaPrehash ecdsa_prehash = 2;\n    CoseOpaqueBytes another = 3;"),
    schema.replace("message CoseEcdsaPrehash {","message CoseEcdsaPrehash {\n  bytes another_digest = 20;"),
    schema.replace('port: "VerificationKey"','port: "MissingPort"'),
    schema.replace('path: "digest"','path: "missing"'),
    schema.replace("identifier: -35","identifier: -7"),
  ]) {
    assert.notEqual(changed,schema);
    writeFileSync(path,changed);
    assert.throws(()=>generate(root),/generation command failed/u);
    assert.deepEqual(snapshot(root),original);
  }
}));
