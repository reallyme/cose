// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { OPERATION_CONTRACT_ROUTES } from "./operation-contract-routes.mjs";

const ADAPTER_ROOT = "crates/cose/src/operation_contract/";

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function blankRange(output, source, start, end) {
  for (let index = start; index < end; index += 1) {
    if (source[index] !== "\n" && source[index] !== "\r") {
      output[index] = " ";
    }
  }
}

// Mask comments and literals before structural checks. This prevents a route
// name in documentation, a diagnostic, or dead string data from satisfying an
// executable-call invariant.
export function maskRustNonCode(source) {
  const output = Array.from(source);
  let index = 0;
  while (index < source.length) {
    if (source.startsWith("//", index)) {
      const end = source.indexOf("\n", index + 2);
      const boundary = end === -1 ? source.length : end;
      blankRange(output, source, index, boundary);
      index = boundary;
      continue;
    }
    if (source.startsWith("/*", index)) {
      let depth = 1;
      let end = index + 2;
      while (end < source.length && depth > 0) {
        if (source.startsWith("/*", end)) {
          depth += 1;
          end += 2;
        } else if (source.startsWith("*/", end)) {
          depth -= 1;
          end += 2;
        } else {
          end += 1;
        }
      }
      blankRange(output, source, index, end);
      index = end;
      continue;
    }

    const raw = /^(?:br|cr|r)(#{0,255})"/u.exec(source.slice(index));
    if (raw !== null) {
      const terminator = `"${raw[1]}`;
      const contentStart = index + raw[0].length;
      const closing = source.indexOf(terminator, contentStart);
      const end = closing === -1 ? source.length : closing + terminator.length;
      blankRange(output, source, index, end);
      index = end;
      continue;
    }

    if (source[index] === '"') {
      let end = index + 1;
      while (end < source.length) {
        if (source[end] === "\\") {
          end += 2;
        } else if (source[end] === '"') {
          end += 1;
          break;
        } else {
          end += 1;
        }
      }
      blankRange(output, source, index, end);
      index = end;
      continue;
    }

    if (source[index] === "'") {
      const character = /^'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^'\\\r\n])'/u.exec(
        source.slice(index),
      );
      if (character !== null) {
        const end = index + character[0].length;
        blankRange(output, source, index, end);
        index = end;
        continue;
      }
    }
    index += 1;
  }
  return output.join("");
}

export function rustFunctionBody(source, functionName) {
  const masked = maskRustNonCode(source);
  const definition = new RegExp(`\\bfn\\s+${escapeRegExp(functionName)}\\s*(?:<[^;{}]*>)?\\s*\\(`, "gu");
  const matches = [...masked.matchAll(definition)];
  if (matches.length !== 1) {
    return null;
  }
  const bodyStart = masked.indexOf("{", matches[0].index + matches[0][0].length);
  const declarationEnd = masked.indexOf(";", matches[0].index + matches[0][0].length);
  if (bodyStart === -1 || (declarationEnd !== -1 && declarationEnd < bodyStart)) {
    return null;
  }
  let depth = 0;
  for (let index = bodyStart; index < masked.length; index += 1) {
    if (masked[index] === "{") {
      depth += 1;
    } else if (masked[index] === "}") {
      depth -= 1;
      if (depth === 0) {
        return masked.slice(bodyStart + 1, index);
      }
    }
  }
  return null;
}

function countMatches(source, pattern) {
  return [...source.matchAll(pattern)].length;
}

function countCalls(source, functionName) {
  return countMatches(source, new RegExp(`\\b${escapeRegExp(functionName)}\\s*\\(`, "gu"));
}

function countReferences(source, identifier) {
  return countMatches(source, new RegExp(`\\b${escapeRegExp(identifier)}\\b`, "gu"));
}

function qualifiedCallPattern(path) {
  const qualified = path.split("::").map(escapeRegExp).join("\\s*::\\s*");
  return new RegExp(`\\b${qualified}\\s*\\(`, "gu");
}

function requireFunction(readText, violations, path, functionName) {
  const body = rustFunctionBody(readText(path), functionName);
  if (body === null) {
    violations.push(`${path} must define exactly one ${functionName} function with a body`);
  }
  return body;
}

function requireExactCalls(violations, path, functionName, body, target, expected = 1) {
  if (body === null) {
    return;
  }
  const count = countCalls(body, target);
  if (count !== expected) {
    violations.push(`${path} ${functionName} must call ${target} exactly ${expected} time(s); found ${count}`);
  }
}

function requireExactReferences(violations, path, functionName, body, target, expected = 1) {
  if (body === null) {
    return;
  }
  const count = countReferences(body, target);
  if (count !== expected) {
    violations.push(`${path} ${functionName} must reference ${target} exactly ${expected} time(s); found ${count}`);
  }
}

export function collectOperationContractRoutingViolations(readText) {
  const violations = [];
  const wirePath = "crates/cose/src/wire.rs";
  const executePath = `${ADAPTER_ROOT}execute.rs`;
  const dispatcher = requireFunction(readText, violations, executePath, "dispatch_operation");
  if (dispatcher !== null) {
    for (const routePolicy of OPERATION_CONTRACT_ROUTES) {
      const variantCount = countReferences(dispatcher, routePolicy.variant);
      if (variantCount !== 1) {
        violations.push(
          `${wirePath} dispatch_operation must dispatch ${routePolicy.variant} exactly once; found ${variantCount}`,
        );
      }
      const adapterModule = routePolicy.adapterPath
        .slice(ADAPTER_ROOT.length, -".rs".length)
        .split("/")
        .join("::");
      const adapterCall = `super::${adapterModule}::${routePolicy.adapterFunction}`;
      const callCount = countMatches(dispatcher, qualifiedCallPattern(adapterCall));
      if (callCount !== 1) {
        violations.push(`${executePath} ${routePolicy.variant} must call ${adapterCall} exactly once; found ${callCount}`);
      }
    }
  }

  for (const [entrypoint, target] of [
    ["execute_operation_proto", "execute_proto"],
    ["execute_operation_proto_json", "execute_proto_json"],
  ]) {
    const body = requireFunction(readText, violations, wirePath, entrypoint);
    requireExactCalls(violations, wirePath, entrypoint, body, target);
  }

  for (const entrypoint of ["execute_proto", "execute_proto_json"]) {
    const body = requireFunction(readText, violations, executePath, entrypoint);
    requireExactReferences(violations, executePath, entrypoint, body, "dispatch_operation");
  }

  const adapterSources = new Map();
  for (const routePolicy of OPERATION_CONTRACT_ROUTES) {
    const source = adapterSources.get(routePolicy.adapterPath) ?? readText(routePolicy.adapterPath);
    adapterSources.set(routePolicy.adapterPath, source);
    const adapterBody = rustFunctionBody(source, routePolicy.adapterFunction);
    if (adapterBody === null) {
      violations.push(`${routePolicy.adapterPath} must define exactly one ${routePolicy.adapterFunction} adapter`);
    } else if (routePolicy.indirect) {
      requireExactCalls(
        violations,
        routePolicy.adapterPath,
        routePolicy.adapterFunction,
        adapterBody,
        "encrypt_result",
      );
      requireExactReferences(
        violations,
        routePolicy.adapterPath,
        routePolicy.adapterFunction,
        adapterBody,
        routePolicy.semanticFunction,
      );
      requireExactReferences(
        violations,
        routePolicy.adapterPath,
        routePolicy.adapterFunction,
        adapterBody,
        routePolicy.resultFunction,
      );
    } else {
      requireExactCalls(
        violations,
        routePolicy.adapterPath,
        routePolicy.adapterFunction,
        adapterBody,
        routePolicy.semanticFunction,
      );
      requireExactCalls(
        violations,
        routePolicy.adapterPath,
        routePolicy.adapterFunction,
        adapterBody,
        routePolicy.resultFunction,
      );
      requireExactReferences(
        violations,
        routePolicy.adapterPath,
        routePolicy.adapterFunction,
        adapterBody,
        "boundary_error_from_failure",
      );
    }

    const nativeSource = readText(routePolicy.nativePath);
    const semanticDefinitions = countMatches(
      maskRustNonCode(nativeSource),
      new RegExp(
        `\\bpub\\s*\\(\\s*crate\\s*\\)\\s+fn\\s+${escapeRegExp(routePolicy.semanticFunction)}\\s*\\(`,
        "gu",
      ),
    );
    if (semanticDefinitions !== 1) {
      violations.push(
        `${routePolicy.nativePath} must define ${routePolicy.semanticFunction} exactly once as pub(crate); found ${semanticDefinitions}`,
      );
    }
    const nativeBody = requireFunction(
      readText,
      violations,
      routePolicy.nativePath,
      routePolicy.nativeFunction,
    );
    requireExactCalls(
      violations,
      routePolicy.nativePath,
      routePolicy.nativeFunction,
      nativeBody,
      routePolicy.semanticFunction,
    );
  }

  const keyHelper = requireFunction(
    readText,
    violations,
    `${ADAPTER_ROOT}key/convert.rs`,
    "parse_request_key",
  );
  requireExactCalls(violations, `${ADAPTER_ROOT}key/convert.rs`, "parse_request_key", keyHelper, "parse_cose_key");
  requireExactReferences(
    violations,
    `${ADAPTER_ROOT}key/convert.rs`,
    "parse_request_key",
    keyHelper,
    "boundary_error_from_failure",
  );

  const encryptHelper = requireFunction(
    readText,
    violations,
    `${ADAPTER_ROOT}encrypt/create.rs`,
    "encrypt_result",
  );
  requireExactCalls(violations, `${ADAPTER_ROOT}encrypt/create.rs`, "encrypt_result", encryptHelper, "operation");
  requireExactCalls(violations, `${ADAPTER_ROOT}encrypt/create.rs`, "encrypt_result", encryptHelper, "convert_result");
  requireExactReferences(
    violations,
    `${ADAPTER_ROOT}encrypt/create.rs`,
    "encrypt_result",
    encryptHelper,
    "boundary_error_from_failure",
  );

  for (const [path, functionName, delegate, forbidden] of [
    [
      "crates/cose/src/encrypt/create.rs",
      "cose_encrypt_ml_kem_direct",
      "cose_encrypt_ml_kem_direct_with_external_aad",
      "encrypt_ml_kem",
    ],
    [
      "crates/cose/src/encrypt/create.rs",
      "cose_encrypt_ml_kem_key_wrap",
      "cose_encrypt_ml_kem_key_wrap_with_external_aad",
      "encrypt_ml_kem",
    ],
    [
      "crates/cose/src/encrypt/decrypt.rs",
      "cose_decrypt_ml_kem",
      "cose_decrypt_ml_kem_with_external_aad",
      "decrypt_ml_kem",
    ],
  ]) {
    const body = requireFunction(readText, violations, path, functionName);
    requireExactCalls(violations, path, functionName, body, delegate);
    requireExactCalls(violations, path, functionName, body, forbidden, 0);
  }

  const bypassedFacades = [
    "cose_key_from_slice",
    "cose_key_from_public_bytes",
    "cose_key_from_private_bytes",
    "cose_key_to_public_bytes",
    "cose_key_to_private_bytes",
    "derive_kid_from_cose_key_public",
    "cose_key_to_multikey",
    "multikey_to_cose_key",
    "cose_sign1_with_options_and_external_aad",
    "cose_sign1_detached_with_options_and_external_aad",
    "cose_verify1_with_policy_and_external_aad",
    "cose_verify1_detached_with_policy_and_external_aad",
    "cose_encrypt_ml_kem_direct_with_external_aad",
    "cose_encrypt_ml_kem_key_wrap_with_external_aad",
    "cose_decrypt_ml_kem_with_external_aad",
  ];
  for (const [path, source] of adapterSources) {
    const code = maskRustNonCode(source);
    for (const facade of bypassedFacades) {
      const count = countCalls(code, facade);
      if (count !== 0) {
        violations.push(`${path} must not call native facade ${facade}; found ${count}`);
      }
    }
    for (const forbiddenPattern of [
      [/_impl\s*\(/gu, "a lower-level *_impl helper"],
      [/\bCoseWireError\s*::/gu, "CoseWireError constructors"],
      [/\bCoseErrorReason\s*::/gu, "CoseErrorReason variants"],
      [/\bCoseFailure\s*::/gu, "CoseFailure constructors"],
      [/\b(?:serde_json|serde)\s*::/gu, "hand-written JSON"],
      [/\b(?:encode_protobuf|decode_protobuf|encode_to_vec)\s*\(/gu, "transport codec calls"],
      [/\bCoseOperationResult\s*\{/gu, "generated result construction"],
    ]) {
      if (forbiddenPattern[0].test(code)) {
        violations.push(`${path} must not contain ${forbiddenPattern[1]}`);
      }
    }
  }

  const verifyAdapter = maskRustNonCode(readText(`${ADAPTER_ROOT}sign1/verify.rs`));
  const cryptoReferences = countMatches(verifyAdapter, /\breallyme_crypto\s*::/gu);
  const constantTimeReferences = countMatches(
    verifyAdapter,
    /\breallyme_crypto\s*::\s*operations\s*::\s*constant_time\s*::\s*equal\s*\(/gu,
  );
  if (cryptoReferences !== 1 || constantTimeReferences !== 1) {
    violations.push(`${ADAPTER_ROOT}sign1/verify.rs may use only one timing-safe kid comparison from reallyme_crypto`);
  }

  return violations;
}

export function assertOperationContractRouting({ readText, fail }) {
  const violations = collectOperationContractRoutingViolations(readText);
  if (violations.length !== 0) {
    fail(`operation-contract routing policy failed: ${violations[0]}`);
  }
}
