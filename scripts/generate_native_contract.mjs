// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { nativeBorrowedProjections, nativeProjections } from "./generate_native_projections.mjs";

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
  const files=generateClosedSelectors(schema);
  files.set("error_aliases.rs",generateErrorAliases(schema).native);
  files.set("constants.rs",generateConstants(schema));
  return new Map([...formattedFiles(files)].map(([name,source])=>[resolve(directory,name),source]));
}

// Buffa remains the wire model. These closed, Copy compatibility selectors are
// emitted from enum metadata so native matching cannot introduce another list.
export function generateClosedSelectors(schema) {
  const files = new Map();
  const modules = ["mod error_aliases;", "mod constants;", '#[cfg(feature="wire")]\npub use constants::CONSTANTS;', "pub use constants::values;"];
  for (const match of schema.matchAll(/\/\/ Rust closed enum: (\w+)\nenum (\w+) \{([\s\S]*?)\n\}/gu)) {
    const [, native, wire, body] = match;
    const prefix = /^\s*(\w+)_UNSPECIFIED = 0;/mu.exec(body)?.[1];
    if (prefix === undefined) throw new TypeError("closed selector requires unspecified zero");
    const values = [];
    const compatibility = [];
    let pending;
    for (const line of body.split("\n")) {
      const variant = /\/\/ Rust variant: (\w+)([^\n]*)/u.exec(line);
      const alias = /\/\/ Rust compatibility variant: (\w+)/u.exec(line);
      if (variant !== null) pending = { name:variant[1],wireId:/; wire: (-?\d+)/u.exec(variant[2])?.[1],compatibilityName:/; alias: (\w+)/u.exec(variant[2])?.[1], hash:/; hash: (\w+)/u.exec(variant[2])?.[1],iso:/; iso(?:;|$)/u.test(variant[2]) };
      if (alias !== null) pending = { name: alias[1], alias: true };
      const field = new RegExp(`^\\s*${prefix}_(\\w+) = (-?\\d+)`, "u").exec(line);
      if (field === null || pending === undefined) continue;
      const value = { ...pending, wireName: title(field[1]), number: field[2] };
      (pending.alias ? compatibility : values).push(value);
      pending = undefined;
    }
    const module = native.replace(/([a-z0-9])([A-Z])/gu, "$1_$2").toLowerCase();
    const variants = values.map((v) => `    /// Schema selector ${v.number}.\n    ${v.name},`).join("\n");
    const from = [...values, ...compatibility].map((v) => `            Some(Wire::${v.wireName}) => Ok(Self::${v.name}),`).join("\n");
    const into = values.map((v) => `            ${native}::${v.name} => Self::${v.wireName},`).join("\n");
    let output = header + `use crate::CoseError;\nuse buffa::EnumValue;\nuse reallyme_cose_proto::generated::proto::reallyme::cose::v1::${wire} as Wire;\n\n/// Closed native view of the authoritative ${wire} selector.\n${body.includes("Rust non-exhaustive") ? "#[non_exhaustive]\n" : ""}#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]\npub enum ${native} {\n${variants}\n}\n\n${compatibility.length === 0 ? "" : "#[allow(deprecated)]\n"}impl TryFrom<EnumValue<Wire>> for ${native} {\n    type Error = CoseError;\n    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {\n        match value.as_known() {\n${from}\n            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),\n        }\n    }\n}\n\nimpl From<${native}> for Wire {\n    fn from(value: ${native}) -> Self {\n        match value {\n${into}\n        }\n    }\n}\n`;
    output += `\nimpl ${native} {\n    /// Complete closed selector set, generated from the schema.\n    pub const ALL: &[Self] = &[${values.map((v) => `Self::${v.name}`).join(", ")}];\n}\n`;
    if (values.every((v) => v.wireId !== undefined)) {
      if (new Set(values.map((v)=>v.wireId)).size!==values.length) throw new TypeError("wire identities must remain distinct");
      output += `\nimpl ${native} {\n    /// Exact COSE wire registration declared by the schema.\n    #[must_use]\n    pub const fn identifier(self) -> i64 {\n        match self {\n${values.map((v) => `            Self::${v.name} => ${v.wireId},`).join("\n")}\n        }\n    }\n    /// Resolve an exact wire identity without profile or provider substitution.\n    ///\n    /// # Errors\n    /// Returns UnsupportedAlgorithm for an unregistered or unsupported identity.\n    pub fn from_identifier(identifier: i64) -> Result<Self, CoseError> {\n        match identifier {\n${values.map((v) => `            ${v.wireId} => Ok(Self::${v.name}),`).join("\n")}\n            _ => Err(CoseError::UnsupportedAlgorithm),\n        }\n    }\n}\n`;
    }
    if (values.some((value)=>value.hash!==undefined || value.iso)) {
      const hashType=/\/\/ Rust closed enum: (\w+)\nenum CoseHashAlgorithm /u.exec(schema)?.[1];
      if (hashType===undefined) throw new TypeError("hash selector missing");
      output+=`\nimpl ${native} {\n    /// Whether this is an original ISO suite registration. Entry points apply their explicit profile.\n    #[must_use]\n    pub const fn is_iso(self)->bool {matches!(self,${values.filter((value)=>value.iso).map((value)=>`Self::${value.name}`).join("|")})}\n    /// ECDSA message hash, independently of named key curve.\n    #[cfg(feature="cose-crypto")]\n    #[must_use]\n    pub const fn ecdsa_hash(self)->Option<super::${hashType}> {match self {\n${values.filter((value)=>value.hash!==undefined).map((value)=>`        Self::${value.name}=>Some(super::${hashType}::${value.hash}),`).join("\n")}\n        _=>None,\n    }}\n}\n`;
    }
    const aliases = values.filter((v) => v.compatibilityName !== undefined);
    if (aliases.length !== 0) output += `\n#[allow(non_upper_case_globals)]\nimpl ${native} {\n${aliases.map((v) => `    /// Compatibility spelling for the canonical point representation.\n    pub const ${v.compatibilityName}: Self = Self::${v.name};`).join("\n")}\n}\n`;
    files.set(`${module}.rs`, output);
    modules.push(moduleExports(module,native,body.includes("Rust availability: core")));
  }
  appendLegacySelectors(schema,files);
  generateClosedValues(schema, files, modules);
  generatePayloadEnums(schema,files,modules);
  generateByteLimits(schema,files,modules);
  for (const projection of [...nativeProjections(schema), ...nativeBorrowedProjections(schema)]) {
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

function generatePayloadEnums(schema, files, modules) {
  for (const [, native, , body] of schema.matchAll(/\/\/ Rust payload enum: (\w+)\nenum (\w+) \{([\s\S]*?)\n\}/gu)) {
    const variants = [...body.matchAll(/\/\/ Rust variant: (\w+)(?:\((\w+)\))?\n\s*\w+ = \d+;/gu)].map(([, name, payload]) => ({name,payload}));
    if (variants.length === 0) throw new TypeError("payload selector metadata missing");
    const module = native.replace(/([a-z0-9])([A-Z])/gu,"$1_$2").toLowerCase();
    const imports = [...new Set(variants.map((variant) => variant.payload).filter(Boolean))];
    const output = header + `use super::{${imports.join(",")}};\n\n/// Closed callback view of the schema selector and its explicit payload.\n${body.includes("Rust non-exhaustive") ? "#[non_exhaustive]\n" : ""}#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]\npub enum ${native} {\n${variants.map((variant) => `    /// Schema-defined ${variant.name} alternative.\n    ${variant.name}${variant.payload === undefined ? "" : `(${variant.payload})`},`).join("\n")}\n}\n`;
    files.set(`${module}.rs`,output);
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

function appendLegacySelectors(schema, files) {
  for (const [,native,wire,body] of schema.matchAll(/\/\/ Rust legacy selector: (\w+)\nenum (\w+) \{([\s\S]*?)\n\}/gu)) {
    const module=native.replace(/([a-z0-9])([A-Z])/gu,"$1_$2").toLowerCase();
    const variants=[...body.matchAll(/\/\/ Rust compatibility variant: (\w+)\n\s*(\w+) = \d+;/gu)];
    const prefix=/^\s*(\w+)_UNSPECIFIED = 0;/mu.exec(body)?.[1];
    if(prefix===undefined || !files.has(`${module}.rs`)) throw new TypeError("legacy selector binding missing");
    const arms=variants.map(([,target,name])=>`            Some(Legacy::${title(name.slice(prefix.length+1))})=>Ok(Self::${target}),`).join("\n");
    files.set(`${module}.rs`,files.get(`${module}.rs`)+`\nimpl TryFrom<buffa::EnumValue<reallyme_cose_proto::generated::proto::reallyme::cose::v1::${wire}>> for ${native} {\n    type Error=crate::CoseError;\n    fn try_from(value:buffa::EnumValue<reallyme_cose_proto::generated::proto::reallyme::cose::v1::${wire}>)->Result<Self,Self::Error> {\n        use reallyme_cose_proto::generated::proto::reallyme::cose::v1::${wire} as Legacy;\n        match value.as_known() {\n${arms}\n            _=>Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),\n        }\n    }\n}\n`);
  }
}
