// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { nativeProjections } from "./generate_native_projections.mjs";
import { nativeAdapterBindings } from "./native_adapter_bindings.mjs";

const header = "// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited\n// SPDX-License-Identifier: MIT OR Apache-2.0\n\n// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.\n\n";
const title = (value) => value.toLowerCase().split("_").map((part) => part[0].toUpperCase() + part.slice(1)).join("");

function formattedFiles(files) {
  const directory=mkdtempSync(join(tmpdir(),"cose-native-contract-"));
  try {
    const paths=[...files.keys()].map((name)=>join(directory,name));
    for(const [name,source] of files) writeFileSync(join(directory,name),source);
    // One formatter process avoids multiplying toolchain startup cost for each
    // projection. Explicit paths and skip_children format every file once.
    const result=spawnSync("rustfmt",["--edition","2021","--config","skip_children=true",...paths],{encoding:"utf8"});
    if(result.status!==0 || result.error!==undefined) throw new TypeError("contract Rust formatting failed");
    return new Map([...files.keys()].map((name)=>[name,readFileSync(join(directory,name),"utf8")]));
  } finally {
    rmSync(directory,{recursive:true,force:true});
  }
}

// Native compatibility names are schema metadata. They carry no independent
// reason identities: the owner and every boundary retain the Buffa enum itself.
export function generateErrorAliases(schema) {
  const body = /enum CoseErrorReason \{([\s\S]*?)\n\}/u.exec(schema)?.[1];
  if (body === undefined) throw new TypeError("canonical error contract missing");
  const reason = [];
  const native = [];
  let aliases = [];
  let errors = [];
  for (const line of body.split("\n")) {
    const alias = /\/\/ Rust reason aliases: (.+)/u.exec(line);
    const error = /\/\/ Rust error alias: (\w+)/u.exec(line);
    if (alias !== null) aliases.push(...alias[1].split(", "));
    if (error !== null) errors.push(error[1]);
    const field = /^\s*COSE_ERROR_REASON_(\w+) = (\d+);/u.exec(line);
    if (field === null) continue;
    const target = title(field[1]);
    for (const name of aliases) {
      if (name !== target) reason.push(`    /// Compatibility spelling for the canonical reason.\n    pub const ${name}: Self = Self::${target};`);
    }
    for (const name of errors) native.push(`    /// Compatibility spelling; the generated reason is retained exactly.\n    pub const ${name}: Self = Self::from_reason(CoseErrorReason::${target});`);
    aliases = []; errors = [];
  }
  return {
    proto: `\n#[allow(non_upper_case_globals)]\nimpl CoseErrorReason {\n${reason.join("\n")}\n}\n`,
    native: header + `use crate::CoseError;\nuse reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseErrorReason;\n\n#[allow(non_upper_case_globals)]\nimpl CoseError {\n${native.join("\n")}\n}\n`,
  };
}

export function nativeContractFiles(root, schema) {
  const directory=resolve(root,"crates/cose/src/generated_contract");
  const files=generateNativeRecords(schema);
  files.set("error_aliases.rs",generateErrorAliases(schema).native);
  files.set("constants.rs",generateConstants(schema));
  return new Map([...formattedFiles(files)].map(([name,source])=>[resolve(directory,name),source]));
}

// Buffa emits every enum. This companion only projects native records and
// assembles modules. The orchestrator copies adapter syntax and applies rustfmt.
function generateNativeRecords(schema) {
  const files = new Map();
  const modules = ["mod error_aliases;", "mod constants;", '#[cfg(feature="wire")]\npub use constants::CONSTANTS;', "pub use constants::values;"];
  for (const adapter of nativeAdapterBindings(schema)) {
    modules.push(moduleExports(adapter.module,adapter.name,adapter.core));
  }
  generateClosedValues(schema, files, modules);
  generateByteLimits(schema,files,modules);
  for (const projection of nativeProjections(schema)) {
    if(files.has(`${projection.module}.rs`)) throw new TypeError("duplicate native declaration");
    files.set(`${projection.module}.rs`, header + projection.source);
    modules.push(moduleExports(projection.module, projection.name, false));
  }
  const declarations=[];
  const exports=new Map();
  for (const entry of modules) {
    const match=/^(#\[cfg\(feature="cose-crypto"\)\]\n)?mod (\w+);\n(?:#\[cfg\(feature="cose-crypto"\)\]\n)?pub use \w+::(\w+);$/u.exec(entry);
    if (match===null) {declarations.push(entry);continue;}
    const [,gate="",module,name]=match;
    declarations.push(`${gate}mod ${module};`);
    if (!exports.has(gate)) exports.set(gate,[]);
    exports.get(gate).push(`${module}::${name}`);
  }
  files.set("mod.rs", header + declarations.join("\n") + "\n" + [...exports].map(([gate,names])=>`${gate}pub use {${names.join(",")}};`).join("\n") + "\n");
  return files;
}

function generateConstants(schema) {
  const entries=[...schema.matchAll(/\/\/ Rust constant: ([a-z0-9_/]+\.rs)#(\w+): (i64|usize)(?:; feature: ([a-z-]+))?\n\s*\/\/ Value: (-?\d+)\n\s*(COSE_IMPLEMENTATION_CONSTANT_\w+) = \d+;/gu)];
  const definitions=entries.map(([, ,name,type,feature,value])=>`    /// Public contract constant.\n${feature===undefined?"":`    #[cfg(feature="${feature}")]\n`}    pub const ${name}: ${type} = ${value};`).join("\n");
  const values=entries.map(([, , , , ,value,variant])=>`    (Wire::${variant}, ${value}),`).join("\n");
  const internal=[...schema.matchAll(/^\/\/ Rust internal limit: (\w+): usize = (\d+)$/gmu)].map(([,name,value])=>`    #[cfg(feature="cose-crypto")]\n    pub(crate) const ${name}: usize = ${value};`).join("\n");
  return header+`#[cfg(feature="wire")]\nuse reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseImplementationConstant as Wire;\n\n#[cfg(feature="wire")]\npub const CONSTANTS: &[(Wire,i64)] = &[\n${values}\n];\n\npub mod values {\n${definitions}\n${internal}\n}\n`;
}

function generateClosedValues(schema, files, modules) {
  const selectors = new Map([...schema.matchAll(/\/\/ Rust closed enum: (\w+)\nenum (\w+) /gu)].map(([, native, wire]) => [wire, native]));
  for (const [, native, wire, body] of schema.matchAll(/\/\/ Rust closed value: (\w+)\nmessage (\w+) \{([\s\S]*?)\n\}/gu)) {
    const fields = [...body.matchAll(/^\s*(\w+) (\w+) = \d+;/gmu)].map(([, type, name]) => ({wire:type, name, native:selectors.get(type)}));
    if (fields.some((field) => field.native === undefined)) throw new TypeError("closed value requires schema selectors");
    const module = native.replace(/([a-z0-9])([A-Z])/gu,"$1_$2").toLowerCase();
    const output = header + `use crate::CoseError;\nuse super::{${fields.map((field) => field.native).join(",")}};\nuse reallyme_cose_proto::generated::proto::reallyme::cose::v1::${wire} as Wire;\n\n/// Closed compatibility value generated from ${wire}.\n#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]\npub struct ${native} {\n${fields.map((field) => `    /// Schema field ${field.name}.\n    pub(crate) ${field.name}: ${field.native},`).join("\n")}\n}\n\nimpl TryFrom<&Wire> for ${native} {\n    type Error=CoseError;\n    fn try_from(value:&Wire)->Result<Self,Self::Error> {\n        Ok(Self {${fields.map((field) => `${field.name}: ${field.native}::try_from(value.${field.name})?`).join(",")}})\n    }\n}\n\nimpl From<${native}> for Wire {\n    fn from(value:${native})->Self {Self {${fields.map((field) => `${field.name}: value.${field.name}.into_wire()`).join(",")}}}\n}\n`;
    // EnumValue conversion composes the one generated closed-selector mapping.
    files.set(`${module}.rs`, output.replace(/value\.(\w+)\.into_wire\(\)/gu, (_, name) => `reallyme_cose_proto::generated::proto::reallyme::cose::v1::${fields.find((field) => field.name===name).wire}::from(value.${name}).into()`));
    modules.push(moduleExports(module,native,body.includes("Rust availability: core")));
  }
}

function generateByteLimits(schema, files, modules) {
  const match = /\/\/ Rust byte limits: (\w+)\nmessage (\w+) \{([\s\S]*?)\n\}/u.exec(schema);
  if (match === null) return;
  const [, native, wire, body] = match;
  const fields=[...body.matchAll(/\/\/ Rust maximum: (\w+)\n\s*uint64 (\w+) = \d+;/gu)].map(([,maximum,name])=>({maximum,name}));
  if (fields.length !== [...body.matchAll(/uint64 \w+ =/gu)].length) throw new TypeError("byte-limit ceiling metadata missing");
  const module=native.replace(/([a-z0-9])([A-Z])/gu,"$1_$2").toLowerCase();
  const output=header+`use crate::CoseError;\nuse super::values;\nuse reallyme_cose_proto::generated::proto::reallyme::cose::v1::${wire} as Wire;\n\n/// Checked native view of the sole portable byte-limit message.\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct ${native} {\n${fields.map((field)=>`    /// Schema-defined ceiling for ${field.name}.\n    pub ${field.name}:usize,`).join("\n")}\n}\nimpl Default for ${native} {\n    fn default()->Self {Self {${fields.map((field)=>`${field.name}:values::${field.maximum}`).join(",")}}}\n}\nimpl TryFrom<&Wire> for ${native} {\n    type Error=CoseError;\n    fn try_from(value:&Wire)->Result<Self,Self::Error> {\n        Ok(Self {\n${fields.map((field)=>`            ${field.name}:usize::try_from(value.${field.name}.min(u64::try_from(values::${field.maximum}).map_err(|_|CoseError::ResourceLimitExceeded)?)).map_err(|_|CoseError::ResourceLimitExceeded)?,`).join("\n")}\n        })\n    }\n}\n`;
  files.set(`${module}.rs`,output);modules.push(moduleExports(module,native,body.includes("Rust availability: core")));
}

function moduleExports(module,native,core) {
  const gate=core?"":'#[cfg(feature="cose-crypto")]\n';
  return `${gate}mod ${module};\n${gate}pub use ${module}::${native};`;
}
