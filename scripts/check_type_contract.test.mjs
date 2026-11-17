// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {readFileSync} from "node:fs";
import test from "node:test";
import {assertCompleteTypeContract} from "./check_type_contract.mjs";
import {generateClosedSelectors,generateErrorAliases} from "./generate_native_contract.mjs";
import {nativeBorrowedProjections,nativeProjections} from "./generate_native_projections.mjs";
import {equalityExtensions,schemaMessageBodies,schemaScalarClassifications} from "./schema_contract.mjs";
import {assertGuardedBuffaContract} from "./check_buffa_contract.mjs";

const files=execFileSync("git",["ls-files","-z"],{encoding:"utf8"}).split("\0").filter(Boolean);
const path="crates/proto/proto/reallyme/cose/v1/cose.proto";
const schema=readFileSync(path,"utf8");
function check(changes=new Map()) {assertCompleteTypeContract({readText:(path)=>changes.get(path)??readFileSync(path,"utf8"),loadTrackedFiles:()=>[...new Set([...files,...changes.keys()])],fail:(message)=>assert.fail(message)});}

test("all public native types and provider methods are schema-reachable",()=>check());
test("native DTO shapes derive from every canonical field, including real presence",()=>{
  const projections=nativeProjections(schema);
  assert.equal(projections.length,17);
  assert.match(projections.find((value)=>value.name==="VerifiedDetachedCoseMac0").source,/Option<zeroize::Zeroizing<Vec<u8>>>/u);
  const changed=nativeProjections(schema.replace("optional bytes protected_kid = 3;","bytes protected_kid = 3;"));
  assert.doesNotMatch(changed.find((value)=>value.name==="VerifiedDetachedCoseMac0").source,/Option</u);
  assert.throws(()=>nativeProjections(schema.replace("message CoseMac0VerifyResult {","message CoseMac0VerifyResult {\n bytes another_value = 20;")),/uncovered projection field/u);
  assert.throws(()=>nativeProjections(schema.replace('"source":"protected_headers","visibility":"internal"','"source":"missing_field","visibility":"internal"')),/missing projection field/u);
  assert.throws(()=>nativeProjections(schema.replace('"source":"protected_headers","visibility":"internal"','"source":"algorithm","visibility":"internal"')),/duplicate projection field/u);
  assert.throws(()=>nativeProjections(schema.replace('"source":"key.context_id","visibility":"internal","width":32','"source":"key.context_id","visibility":"internal","width":33')),/fixed width/u);
  const source="crates/cose/src/mac0/types.rs";
  assert.throws(()=>check(new Map([[source,readFileSync(source,"utf8")+"\npub struct VerifiedDetachedCoseMac0 { another_value: u8 }\n"]])),/must be generated/u);
});
test("borrowed content and callback alternatives cannot drift from their generated contract",()=>{
  assert.equal(nativeBorrowedProjections(schema).length,5);
  assert.throws(()=>nativeBorrowedProjections(schema.replace("COSE_CONTENT_MODE_DETACHED = 2;","COSE_CONTENT_MODE_DETACHED = 2;\n COSE_CONTENT_MODE_ANOTHER = 3;")),/every canonical alternative/u);
  assert.throws(()=>nativeBorrowedProjections(schema.replace("CoseEcdsaPrehash ecdsa_prehash = 2;","CoseEcdsaPrehash ecdsa_prehash = 2;\n CoseOpaqueBytes another = 3;")),/every canonical alternative/u);
  assert.throws(()=>nativeBorrowedProjections(schema.replace('"port":"VerificationKey"','"port":"MissingPort"')),/capability port/u);
  assert.throws(()=>nativeBorrowedProjections(schema.replace('"field":"CoseSigningInput.message.encoded"','"field":"CoseSigningInput.message.missing"')),/missing borrowed/u);
  assert.throws(()=>nativeBorrowedProjections(schema.replace("message CoseEcdsaPrehash {","message CoseEcdsaPrehash {\n bytes another_digest = 20;")),/uncovered payload field/u);
});
test("an annotation cannot authorize a second owned request or policy model",()=>{
  const source="crates/cose/src/policy/validate.rs";
  assert.throws(()=>check(new Map([[source,readFileSync(source,"utf8").replace("contract: ContractPolicy,","contract: ContractPolicy,\n    allow_any: bool,")]])),/only its Buffa contract/u);
  const another="crates/cose/src/another_request.rs";
  assert.throws(()=>check(new Map([[path,schema+"\n// Rust view: another_request.rs#AnotherRequest\n"],[another,"pub struct AnotherRequest { pub input: Vec<u8> }\n"]])),/must derive from protobuf fields/u);
  const owner="crates/cose/src/containers/agreement_key.rs";
  assert.throws(()=>check(new Map([[owner,readFileSync(owner,"utf8").replace("pub struct AgreementKey {","pub struct AgreementKey {\n    pub bypass: u32,")]])),/parallel DTO fields/u);
});
test("native cleanup requires every schema field and destruction owner",()=>{
  const generatedPath="crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs";
  const generated=readFileSync(generatedPath,"utf8");
  const validate=(changed)=>assertGuardedBuffaContract({root:process.cwd(),readText:(name)=>name===generatedPath?changed:readFileSync(name,"utf8"),fail:(message)=>assert.fail(message),assertWorkflowRunStep:()=>{}},false);
  assert.doesNotThrow(()=>validate(generated));
  assert.equal(schemaScalarClassifications(schema).find((value)=>value.message==="CoseSign1CreateRequest" && value.field==="kid")?.sensitivity,"sensitive");
  for(const changed of [
    generated.replace("pub private_key: crate::SecretBytes,","pub private_key: Vec<u8>,"),
    generated.replace("impl ::buffa::sensitive::ZeroizeOnDrop for CoseSign1CreateRequest", "impl Removed for CoseSign1CreateRequest"),
    generated.replace("impl ::core::ops::Drop for CoseSign1CreateRequest", "impl Removed for CoseSign1CreateRequest"),
  ]) {
    assert.notEqual(changed,generated);
    assert.throws(()=>validate(changed),/wipe owner|native Drop|cleanup family/u);
  }
});
test("schema ownership scopes empty messages and ignores comment braces",()=>{
  const source=`message Empty {}
message Actual {
 // This brace } is not a scope boundary.
 oneof value {
  // SENSITIVE: exact bytes.
  bytes standalone = 1;
 }
}
`;
  assert.equal(schemaMessageBodies(source).get("Empty"),"");
  assert.equal(schemaScalarClassifications(source).length,1);
  assert.deepEqual(schemaScalarClassifications(source)[0],{message:"Actual",field:"standalone",kind:"bytes",sensitivity:"sensitive"});
  assert.throws(()=>schemaMessageBodies("message Broken {"),/unterminated/u);
});
test("oneof scalar ownership follows the generated type path for digit-bearing names",()=>{
  const generatedPath="crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs";
  const oneofPath="crates/proto/src/generated/buffa/reallyme.cose.v1.cose.__oneof.rs";
  const generated=readFileSync(generatedPath,"utf8");
  const oneofs=readFileSync(oneofPath,"utf8");
  const validate=(changes)=>assertGuardedBuffaContract({root:process.cwd(),readText:(name)=>changes.get(name)??readFileSync(name,"utf8"),fail:(message)=>assert.fail(message),assertWorkflowRunStep:()=>{}},false);
  validate(new Map());
  const marker="pub mod cose_counter_signature0verify_request {";
  const start=oneofs.indexOf(marker);
  assert.notEqual(start,-1);
  const unguarded=oneofs.slice(0,start)+oneofs.slice(start).replace("Standalone(crate::SecretBytes)","Standalone(::std::vec::Vec<u8>)");
  assert.notEqual(unguarded,oneofs);
  assert.throws(()=>validate(new Map([[oneofPath,unguarded]])),/native wipe owner/u);
  const missing=generated.replace("Option<__buffa::oneof::cose_counter_signature0verify_request::Signature>","Option<__buffa::oneof::missing_counter_owner::Signature>");
  assert.notEqual(missing,generated);
  assert.throws(()=>validate(new Map([[generatedPath,missing]])),/native wipe owner/u);
});
test("handwritten presence flags cannot return to the schema",()=>{
  assert.throws(()=>check(new Map([[path,schema.replace("message CoseMac0VerifyResult {", "message CoseMac0VerifyResult {\n bool has_another_value = 19;")]])),/scalar presence/u);
});
test("retired presence flag numbers and names remain reserved",()=>{
  for (const [message,number,name] of [
    ["CoseSign1CreateRequest",5,"has_kid"],
    ["CoseSign1CreateDetachedRequest",5,"has_kid"],
    ["CoseKeyFromPrivateBytesRequest",4,"has_public_key"],
    ["CoseMlKemEncryptRequest",8,"has_supp_priv_info"],
    ["CoseMlKemDecryptRequest",6,"has_supp_priv_info"],
    ["CoseMac0VerifyResult",4,"has_protected_kid"],
    ["CoseIsoSign1VerifyResult",4,"has_protected_kid"],
    ["CoseIsoSign1VerifyResult",6,"has_attached_payload"],
    ["CoseContainerVerifyResult",11,"has_certificate_sha256"],
    ["CoseSign1VerifyResult",5,"has_exact_signature_algorithm"],
    ["CoseKeyBytesResult",3,"has_signature_algorithm"],
  ]) {
    const body=new RegExp(`message ${message} \\{([\\s\\S]*?)\\n\\}`,"u").exec(schema)?.[1];
    assert.equal(typeof body,"string");
    assert.ok(body.includes(`reserved ${number};`));
    assert.ok(body.includes(`reserved "${name}";`));
  }
});
test("adding an associated public operation requires an explicit schema binding",()=>{
  const source="crates/cose/src/policy/validate.rs";
  assert.throws(()=>check(new Map([[source,readFileSync(source,"utf8")+"\nimpl CosePolicy { pub fn unrelated_operation(&self) {} }\n"]])),/needs a protobuf contract/u);
});
test("value projections cannot reference a missing schema type or method",()=>{
  assert.throws(()=>check(new Map([[path,schema.replace("=> CoseVerificationPolicy: new", "=> MissingPolicy: new")]])),/missing protobuf type/u);
  assert.throws(()=>check(new Map([[path,schema.replace("=> CoseVerificationPolicy: new", "=> CoseVerificationPolicy: missing, new")]])),/stale protobuf value method/u);
});
test("an operation route does not authorize a handwritten public selector",()=>{
  assert.throws(()=>check(new Map([["crates/cose/src/another_selector.rs","pub enum AnotherSelector { One, Two }\n"]])),/must be generated/u);
});
test("a public error cannot grow another handwritten reason enum",()=>{
  assert.throws(()=>check(new Map([["crates/cose/src/another_error.rs","pub enum AnotherErrorReason { Failed }\n"]])),/must be generated/u);
});
test("aliases and nested public types cannot hide a parallel contract",()=>{
  assert.throws(()=>check(new Map([["crates/cose/src/another_alias.rs","pub type UntypedError = String;\n"]])),/canonical contract type/u);
  assert.throws(()=>check(new Map([["crates/cose/src/another_owner.rs","pub mod nested {\n    pub struct AnotherOwner { value: u64 }\n}\n"]])),/authoritative protobuf view/u);
});
test("a borrowed-view annotation cannot authorize an owned selector",()=>{
  const changed=schema.replace("message CoseProviderRegistry {","// Rust borrowed view: another_selector.rs#AnotherSelector\nmessage CoseProviderRegistry {");
  assert.throws(()=>check(new Map([[path,changed],["crates/cose/src/another_selector.rs","pub enum AnotherSelector { One }\n"]])),/must be generated/u);
});
test("every provider method requires its generated callback field",()=>{
  const source="crates/cose/src/operation_contract/providers.rs";
  assert.throws(()=>check(new Map([[source,readFileSync(source,"utf8").replace("pub trait OperationProviders {","pub trait OperationProviders {\n fn hidden_callback(&self);\n")]])),/needs a protobuf callback/u);
});
test("provider callback targets must exist in the schema",()=>{
  assert.throws(()=>check(new Map([[path,schema.replace("=> CoseProviderCallRequest.sign","=> CoseProviderCallRequest.missing")]])),/missing protobuf field/u);
});
test("provider reason identity cannot migrate into a primitive family band",()=>{
  assert.throws(()=>check(new Map([[path,schema.replace("COSE_ERROR_REASON_PROVIDER_UNAVAILABLE = 201;","COSE_ERROR_REASON_PROVIDER_UNAVAILABLE = 908;")]])),/numeric band disagree/u);
});
test("typ requires a generated oneof and constants require schema generation",()=>{
  assert.throws(()=>check(new Map([[path,schema.replace("oneof value {","oneof wrong {")]])),/protobuf oneof/u);
  assert.throws(()=>check(new Map([["crates/cose/src/another_constant.rs","pub const UNDECLARED_LIMIT: usize = 7;\n"]])),/must derive from protobuf/u);
});
test("native selectors and aliases derive from the one schema list",()=>{
  const original=generateClosedSelectors(schema).get("cose_signature_algorithm.rs");
  const changed=generateClosedSelectors(schema.replace("wire: -35","wire: -351")).get("cose_signature_algorithm.rs");
  assert.equal(typeof original,"string");assert.notEqual(original,changed);
  assert.throws(()=>generateClosedSelectors(schema.replace("wire: -35","wire: -7")),/remain distinct/u);
  const errors=generateErrorAliases(schema);
  assert.match(errors.proto,/MalformedCbor: Self = Self::CommonCbor/u);
  assert.match(errors.native,/Cbor: Self = Self::from_reason\(CoseErrorReason::CommonCbor\)/u);
});
test("native Eq compatibility cannot hide a floating-point schema change",()=>{
  assert.throws(()=>equalityExtensions(schema.replace("uint64 content_format = 2;","double content_format = 2;")),/equality-safe/u);
});
