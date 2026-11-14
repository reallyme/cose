// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

import { maskRustNonCode } from "./release-readiness/operation-contract-routing.mjs";
import { nativeBorrowedProjections, nativeProjections } from "./generate_native_projections.mjs";

// Native selectors, borrowed alternatives and DTO declarations derive from the
// schema. Only process-local owners and provider ports remain handwritten.
export function assertCompleteTypeContract({readText,loadTrackedFiles,fail}) {
  const schema=readText("crates/proto/proto/reallyme/cose/v1/cose.proto");
  if (/^\s*bool has_\w+\s*=/mu.test(schema)) fail("scalar presence must use optional, a oneof or UNSPECIFIED");
  const projections=[...nativeProjections(schema),...nativeBorrowedProjections(schema)];
  const projectionBindings=new Set(projections.map((value)=>`${value.path}#${value.name}`));
  const messages=new Map([...schema.matchAll(/(?:message|enum) (\w+) \{([\s\S]*?)\n\}/gu)].map(([,name,body])=>[name,body]));
  const views=new Set([...schema.matchAll(/\/\/ Rust view: ([a-z0-9_/]+\.rs)#(\w+)/gu)].map(([,path,name])=>`${path}#${name}`));
  const borrowed=new Set([...schema.matchAll(/\/\/ Rust borrowed view: ([a-z0-9_/]+\.rs)#(\w+)/gu)].map(([,path,name])=>`${path}#${name}`));
  const owners=new Map([...schema.matchAll(/\/\/ Rust message owner: ([a-z0-9_/]+\.rs)#(\w+) => (\w+)/gu)].map(([,path,name,message])=>[`${path}#${name}`,message]));
  const capabilities=new Set([...schema.matchAll(/\/\/ Rust capability owner: ([a-z0-9_/]+\.rs)#(\w+)/gu)].map(([,path,name])=>`${path}#${name}`));
  const ports=new Set([...schema.matchAll(/\/\/ Rust port: ([a-z0-9_/]+\.rs)#(\w+)/gu)].map(([,path,name])=>`${path}#${name}`));
  const canonicalTypes=new Set([
    ...[...views].map((identity)=>identity.split("#")[1]),
    ...[...schema.matchAll(/\/\/ Rust (?:closed enum|closed value|payload enum|byte limits): (\w+)/gu)].map(([,name])=>name),
  ]);
  const methods=new Map([...schema.matchAll(/\/\/ Rust port method: ([a-z0-9_/]+\.rs)#(\w+)\.(\w+) => (\w+)(?:\.(\w+))?/gu)].map(([,path,name,method,message,field])=>[`${path}#${name}.${method}`,{message,field}]));
  const adapters=new Set([...schema.matchAll(/\/\/ Rust adapter: ([a-z0-9_/]+\.rs)#(\w+)/gu)].map(([,path,name])=>`${path}#${name}`));
  const values=new Set();
  for (const [,path,owner,message,names] of schema.matchAll(/\/\/ Rust value methods: ([a-z0-9_/]+\.rs)#(\w+) => (\w+): ([\w, ]+)/gu)) {
    if (!messages.has(message)) fail("value method references a missing protobuf type");
    for (const method of names.split(", ")) {
      const identity=`${path}#${owner}.${method}`;
      if (values.has(identity)) fail(`duplicate protobuf value method ${identity}`);
      values.add(identity);
    }
  }
  for (const {message,field} of methods.values()) {
    const body=messages.get(message);
    if (body===undefined || (field!==undefined && !new RegExp(`\\b${field} = \\d+;`,"u").test(body))) fail("provider method references a missing protobuf field");
  }
  const seen=new Set();const seenMethods=new Set();
  for (const path of loadTrackedFiles()) {
    if (!path.startsWith("crates/cose/src/") || !path.endsWith(".rs") || /(?:tests|test_support)\.rs$/u.test(path) || path.includes("/generated_contract/")) continue;
    const source=maskRustNonCode(readText(path));
    for (const projection of projections.filter((value)=>path===`crates/cose/src/${value.path}`)) {
      if (!new RegExp(`pub use crate::generated_contract::${projection.name};`,"u").test(source)) fail(`native projection ${projection.name} must reexport its generated declaration`);
      seen.add(`${projection.path}#${projection.name}`);
    }
    for (const match of source.matchAll(/^\s*pub (enum|struct|trait) (\w+)([^\n{;]*)/gmu)) {
      const [,kind,name,parameters]=match;
      const identity=`${path.slice("crates/cose/src/".length)}#${name}`;
      if (projectionBindings.has(identity)) fail(`native projection ${identity} must be generated from protobuf fields`);
      seen.add(identity);
      if (kind==="enum") {
        fail(`public enum ${identity} must be generated from protobuf`);
      } else if (kind==="trait") {
        if (!ports.has(identity)) fail(`public port ${identity} needs a generated callback contract`);
        const start=source.indexOf("{",match.index);let cursor=start+1;let depth=1;
        while (depth!==0 && cursor<source.length) {if (source[cursor]==="{") depth+=1; else if (source[cursor]==="}") depth-=1;cursor+=1;}
        for (const method of source.slice(start+1,cursor-1).matchAll(/\bfn\s+(\w+)\b/gu)) {
          if (!methods.has(`${identity}.${method[1]}`)) fail(`public provider method ${identity}.${method[1]} needs a protobuf callback`);
        }
      } else {
        if (!views.has(identity)) fail(`public type ${identity} needs an authoritative protobuf view`);
        const start=source.indexOf("{",match.index);let end=start+1;let depth=1;
        const unit=source.slice(match.index,source.indexOf("\n",match.index)).includes(";");
        if (!unit) while(depth!==0 && end<source.length) {if(source[end]==="{")depth+=1;else if(source[end]==="}")depth-=1;end+=1;}
        const body=unit?"":source.slice(start+1,end-1);
        if (owners.has(identity)) {
          const message=owners.get(identity);
          const owner=/^\s*contract:\s*([\w:]+),?\s*$/u.exec(body)?.[1];
          const name=owner?.split("::").at(-1);
          const alias=name===undefined?undefined:new RegExp(`\\b${message} as ${name}\\b`,"u");
          if (!messages.has(message) || owner===undefined || (name!==message && !alias.test(source))) fail(`message owner ${identity} must contain only its Buffa contract`);
        } else if (borrowed.has(identity) && parameters.includes("<'")) {
          // A parsed span or borrowed provider selection retains lifetimes;
          // it cannot introduce owned wire-message fields.
          if (/\b(?:Vec|String|Box|Zeroizing)\s*</u.test(body)) fail(`borrowed view ${identity} cannot own a parallel DTO`);
        } else if (capabilities.has(identity)) {
          if (/\bpub\s+\w+\s*:/u.test(body)) fail(`capability owner ${identity} cannot expose parallel DTO fields`);
        } else fail(`public DTO ${identity} must derive from protobuf fields`);
      }
    }
    for (const [,name,target] of source.matchAll(/\bpub\s+type\s+(\w+)\s*=\s*([^;]+);/gu)) {
      if (!/^\w+(?:::\w+)*$/u.test(target.trim()) || !canonicalTypes.has(target.trim().split("::").at(-1))) fail(`public alias ${name} must name a canonical contract type`);
    }
    for (const {owner,method} of nativePublicMethods(path,source)) {
      const relative=path.slice("crates/cose/src/".length);
      const identity=`${relative}#${owner}.${method}`;
      seenMethods.add(identity);
      if (!values.has(identity) && !adapters.has(`${relative}#${method}`)) fail(`public method ${identity} needs a protobuf contract`);
    }
    if (/\bpub const (?!fn\b)\w+\s*:[^;=]+=/u.test(source)) fail(`public constants in ${path} must derive from protobuf`);
    if (/enum (?:CoseFailureReason|ContainerErrorReason|CoseMac0ErrorReason|CoseSignerError)\b/u.test(source)) fail("duplicate handwritten error reasons are forbidden");
  }
  for (const identity of [...views,...borrowed,...ports]) if (!seen.has(identity)) fail(`stale protobuf type binding ${identity}`);
  for (const identity of values) if (!seenMethods.has(identity)) fail(`stale protobuf value method ${identity}`);
  if (messages.has("CoseSignatureRegistration") || messages.has("CoseAgreementCurve")) fail("parallel algorithm and curve selectors are forbidden");
  const reasons=messages.get("CoseErrorReason")??"";
  for (const [,name,number] of reasons.matchAll(/COSE_ERROR_REASON_(\w+) = (\d+);/gu)) {
    const code=Number(number);
    if ((name.startsWith("PROVIDER_") && (code<200 || code>=300)) || (name.startsWith("BACKEND_") && (code<300 || code>=400))) fail("failure branch and numeric band disagree");
    if (/^(?:MAC0|CONTAINER)_(?:MALFORMED|ENCODING$|DUPLICATE$|CRITICAL$|LIMIT$|ALGORITHM$|KEY$|PROVIDER|BACKEND)/u.test(name)) fail("shared failures must not be duplicated by a container family");
  }
  if (!/message CoseType \{\s*oneof value \{/u.test(schema)) fail("typ alternatives require a protobuf oneof");
  if (/^\s*bool has_\w+\s*=/mu.test(schema)) fail("scalar presence must use optional, a oneof or UNSPECIFIED");
  if (/allowed_algs\b/u.test(readText("crates/cose/src/policy/validate.rs"))) fail("policy must retain one exact-registration allowlist");
}

export function nativePublicMethods(path, source) {
  const code=maskRustNonCode(source);
  const result=[];
  for (const match of code.matchAll(/\bimpl(?:\s*<[^{}]*?>)?\s+(\w+)(?:\s*<[^{}]*?>)?\s*\{/gu)) {
    let cursor=match.index+match[0].length;const start=cursor;let depth=1;
    while (depth!==0 && cursor<code.length) {if(code[cursor]==="{")depth+=1;else if(code[cursor]==="}")depth-=1;cursor+=1;}
    if(depth!==0) throw new TypeError("unbalanced Rust implementation");
    for (const method of code.slice(start,cursor-1).matchAll(/^\s*pub(?!\s*\()[^{}\n;]*?\bfn\s+(\w+)\b/gmu)) result.push({path,owner:match[1],method:method[1],index:start+method.index+method[0].indexOf("fn")});
  }
  return result;
}
