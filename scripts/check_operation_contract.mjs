// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

import { maskRustNonCode, rustFunctionBody } from "./release-readiness/operation-contract-routing.mjs";
import { nativePublicMethods } from "./check_type_contract.mjs";

// Adapter declarations live beside their operation in protobuf. This guard
// rejects an unrepresented public operation rather than accepting a second
// handwritten registry as the authority for the generated contract.
export function assertCompleteOperationContract({ readText, loadTrackedFiles, fail }) {
  const schema = readText("crates/proto/proto/reallyme/cose/v1/cose.proto");
  const requests = /message CoseOperationRequest \{([\s\S]*?)\n\}/u.exec(schema)?.[1];
  const results = /message CoseOperationResult \{([\s\S]*?)\n\}/u.exec(schema)?.[1];
  if (requests === undefined || results === undefined) fail("generated operation envelopes are required");
  const fields = (body) => new Map([...body.matchAll(/^\s+\w+ (\w+) = (\d+);/gmu)].map((m) => [m[1], m[2]]));
  const requestFields = fields(requests);
  const resultFields = fields(results);
  if (requestFields.size !== resultFields.size) fail("every generated request needs its own result");
  const dispatcher = maskRustNonCode(readText("crates/cose/src/operation_contract/execute.rs"));
  const response = maskRustNonCode(readText("crates/cose/src/operation_contract/response_v2.rs"));
  const variant = (name) => name.split("_").map((part) => part[0].toUpperCase() + part.slice(1)).join("");
  for (const [name, number] of requestFields) {
    if (resultFields.get(name) !== number) fail(`operation/result identity differs for ${name}`);
    const identity = variant(name);
    if ([...dispatcher.matchAll(new RegExp(`Operation::${identity}\\s*\\(`, "gu"))].length !== 1) {
      fail(`generated operation ${name} must have exactly one dispatch arm`);
    }
    if (!new RegExp(`CoseOperationResultBranch::${identity}\\s*\\(`, "u").test(response)) {
      fail(`generated operation ${name} lacks response validation/pairing`);
    }
  }
  const adapters = new Set();
  for (const match of requests.matchAll(/\/\/ Rust adapter: ([a-z0-9_/]+\.rs)#(\w+)/gu)) {
    const [, relative, name] = match;
    const identity = `${relative}#${name}`;
    if (adapters.has(identity)) fail(`duplicate native contract adapter ${identity}`);
    adapters.add(identity);
    const path = `crates/cose/src/${relative}`;
    const source = readText(path);
    const code = maskRustNonCode(source);
    // Trait implementations can contain private methods with the same name as
    // a public owner adapter. Restrict this check to the declared public entry.
    const publicOnly = code.replace(new RegExp(`\\bfn\\s+${name}\\s*\\(`, "gu"), (match, offset) =>
      code.slice(0, offset).trimEnd().endsWith("pub") ? match : match.replace(name, "__private_contract_method"),
    );
    const body = rustFunctionBody(publicOnly, name);
    if (body === null) fail(`schema-declared adapter ${identity} does not exist`);
    if (body.split("\n").length > 60) fail(`schema adapter ${identity} must delegate to focused semantic logic`);
  }
  const transports=new Set();
  for (const [,relative,name,message] of schema.matchAll(/\/\/ Rust transport adapter: ([a-z0-9_/]+\.rs)#(\w+) => (\w+)/gu)) {
    if (!new RegExp(`message ${message} \\{`,"u").test(schema)) fail("transport adapter needs a generated message");
    const identity=`${relative}#${name}`;
    if (transports.has(identity)) fail("duplicate transport adapter");
    const body=rustFunctionBody(readText(`crates/cose/src/${relative}`),name);
    if (body===null || body.split("\n").length>60) fail(`transport adapter ${identity} must remain a thin generated-contract boundary`);
    transports.add(identity);
  }
  for (const path of loadTrackedFiles()) {
    if (!path.startsWith("crates/cose/src/") || !path.endsWith(".rs") || path.includes("/generated_contract/") || /(?:tests|test_support)\.rs$/u.test(path)) continue;
    const code=maskRustNonCode(readText(path));
    const methods=new Set(nativePublicMethods(path,code).map((method)=>method.index));
    for (const match of code.matchAll(/\bpub\s+(?:(?:async|const|unsafe|extern)\s+)*fn\s+(\w+)/gu)) {
      if (methods.has(match.index+match[0].indexOf("fn"))) continue;
      const identity = `${path.slice("crates/cose/src/".length)}#${match[1]}`;
      if (!adapters.has(identity) && !transports.has(identity)) fail(`public operation ${identity} needs a protobuf contract`);
    }
  }
}
