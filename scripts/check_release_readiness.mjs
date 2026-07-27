#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { isDeepStrictEqual } from "node:util";

import { createReleaseReadinessContext } from "./release-readiness/core.mjs";
import { assertOperationContractRouting } from "./release-readiness/operation-contract-routing.mjs";

const {
  readText,
  readJson,
  fail,
  loadTrackedFiles,
  assertContains,
  assertNotContains,
  assertNotMatches,
  runCommands,
  assertProtoContract,
  assertNodeWorkflowJobsPinNode,
  assertReallyMeProtobufReleasePolicy,
  assertWorkflowActionsPinned,
  assertCargoFuzzWorkflowPolicy,
  assertReallyMeVendoredCorePolicy,
  assertTextPolicy,
  assertCargoMetadataPolicy,
} = createReleaseReadinessContext({
  scriptUrl: import.meta.url,
  requireTrackedFiles: true,
});

// The workflow `uses` lines are the single source of truth for action identities.
// Enforcing immutable SHAs here preserves supply-chain review without duplicating
// each SHA in policy code, which would make legitimate Dependabot updates fail CI.
assertWorkflowActionsPinned();
assertCargoFuzzWorkflowPolicy({
  version: "0.13.2",
  requiredInstallSteps: [
    { job: "build", name: "Install cargo-fuzz" },
    { job: "scheduled", name: "Install cargo-fuzz" },
  ],
});
assertReallyMeVendoredCorePolicy();
assertContains(".github/dependabot.yml", "groups:");
assertContains(".github/dependabot.yml", "github-actions:");

const expectedPackageName = "reallyme-cose";
const expectedProtoPackageName = "reallyme-cose-proto";
const expectedVersion = "0.2.0";
const generatedFreshnessMode = process.argv.includes("--generated-freshness");
const policyOnlyMode = process.argv.includes("--policy-only");
const releasePackagesMode = process.argv.includes("--release-packages");
const selectedModes = [generatedFreshnessMode, policyOnlyMode, releasePackagesMode].filter(Boolean);
const supportedArguments = new Set([
  "--generated-freshness",
  "--policy-only",
  "--release-packages",
]);
if (process.argv.slice(2).some((argument) => !supportedArguments.has(argument))) {
  fail("release readiness received an unsupported mode");
}
if (selectedModes.length > 1) {
  fail("release readiness modes are mutually exclusive");
}
const verifiedBufInstallCommand = `set -euo pipefail
install_dir="$RUNNER_TEMP/buf/bin"
mkdir -p "$install_dir"
curl --fail-with-body --location --proto '=https' --tlsv1.2 \\
  --retry 5 --retry-all-errors \\
  --output "$install_dir/buf" \\
  "https://github.com/bufbuild/buf/releases/download/v\${BUF_VERSION}/buf-Linux-x86_64"
printf '%s  %s\\n' "$BUF_LINUX_X86_64_SHA256" "$install_dir/buf" \\
  | sha256sum --check --strict
chmod 0755 "$install_dir/buf"
printf '%s\\n' "$install_dir" >> "$GITHUB_PATH"
"$install_dir/buf" --version`;

const expectedPlatformScope = {
  schema: "reallyme.cose.platform_scope.v1",
  spdxCopyrightText: "Copyright © 2026 ReallyMe LLC. All rights reserved",
  spdxLicenseIdentifier: "Apache-2.0",
  release: expectedVersion,
  immediateScope: "rust_and_protobuf",
  publishableCrates: [expectedProtoPackageName, expectedPackageName],
  rustRuntimeLanes: ["native", "wasm"],
  platformLanes: [
    { lane: "swift", decision: "planned_later_release" },
    { lane: "android_kotlin", decision: "planned_later_release" },
    { lane: "kotlin_jvm", decision: "planned_later_release" },
    { lane: "native_abi", decision: "not_approved" },
    { lane: "typescript_wasm_npm", decision: "not_approved" },
  ],
  protobufSwiftMetadataIsPackagingApproval: false,
  wasmRuntimeIsNpmPackagingApproval: false,
};
const platformScopePath = "docs/platform-scope-0.2.0.json";
const platformScope = readJson(platformScopePath);
if (!isDeepStrictEqual(platformScope, expectedPlatformScope)) {
  fail(`${platformScopePath} must exactly match the approved 0.2.0 platform scope`);
}

const forbiddenPlatformPathPrefixes = [
  "packages/",
  "sdk/",
  "sdks/",
  "crates/ffi/",
  "crates/jni/",
  "crates/reallyme-cose-ffi/",
  "crates/reallyme-cose-jni/",
  "crates/cose/src/ffi/",
  "crates/cose/src/jni/",
];
const forbiddenPlatformPaths = new Set(["crates/cose/src/ffi.rs", "crates/cose/src/jni.rs"]);
const forbiddenPlatformManifestNames = new Set([
  "Package.swift",
  "build.gradle",
  "build.gradle.kts",
  "settings.gradle",
  "settings.gradle.kts",
  "gradlew",
  "pom.xml",
]);
for (const trackedFile of loadTrackedFiles()) {
  const manifestName = trackedFile.slice(trackedFile.lastIndexOf("/") + 1);
  if (
    forbiddenPlatformPathPrefixes.some((prefix) => trackedFile.startsWith(prefix)) ||
    forbiddenPlatformPaths.has(trackedFile) ||
    forbiddenPlatformManifestNames.has(manifestName)
  ) {
    fail(`${trackedFile} is outside the approved Rust/protobuf-only 0.2.0 scope`);
  }
}

for (const obsoleteRoot of ["benches/", "conformance/", "src/", "tests/"]) {
  for (const trackedFile of loadTrackedFiles()) {
    if (trackedFile.startsWith(obsoleteRoot)) {
      fail(`${trackedFile} is outside the canonical workspace layout`);
    }
  }
}

const MAX_HAND_WRITTEN_RUST_LINES = 500;
const inlineTestModulePattern =
  /#\[cfg\(test\)\]\s*(?:#\[[^\]]+\]\s*)*mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/u;
for (const trackedFile of loadTrackedFiles()) {
  if (!trackedFile.startsWith("crates/cose/src/") || !trackedFile.endsWith(".rs")) {
    continue;
  }
  const source = readText(trackedFile);
  const lineCount = source.split("\n").length;
  if (lineCount > MAX_HAND_WRITTEN_RUST_LINES) {
    fail(
      `${trackedFile} has ${lineCount} lines; hand-written Rust modules are capped at ${MAX_HAND_WRITTEN_RUST_LINES}`,
    );
  }
  if (inlineTestModulePattern.test(source)) {
    fail(`${trackedFile} must place substantive test modules in a dedicated source file`);
  }
}
for (const forbiddenPlatformFeature of ["swift", "kotlin", "android", "jni", "ffi"]) {
  assertNotMatches(
    "crates/cose/Cargo.toml",
    new RegExp(`^${forbiddenPlatformFeature}\\s*=`, "mu"),
    `a Rust ${forbiddenPlatformFeature} feature`,
  );
}
assertNotMatches(
  "crates/cose/Cargo.toml",
  /\bcrate-type\s*=\s*\[[^\]]*"(?:cdylib|staticlib)"/su,
  "a platform-native Rust library artifact",
);
assertContains("README.md", "## 0.2.0 Platform Scope");
assertContains(
  "README.md",
  "The `0.2.0` distribution does not include Swift, Android/Kotlin, Kotlin/JVM",
);

assertNodeWorkflowJobsPinNode({ nodeVersion: "24" });

assertContains("Cargo.toml", 'default-members = ["crates/cose"]');
assertContains("Cargo.toml", 'members = ["crates/cose", "crates/proto"]');
assertContains("Cargo.toml", 'repository = "https://github.com/reallyme/cose"');
assertNotMatches("Cargo.toml", /^\[package\]$/mu, "a package at the workspace root");
assertContains("crates/cose/Cargo.toml", `name = "${expectedPackageName}"`);
assertContains("crates/cose/Cargo.toml", `version = "${expectedVersion}"`);
assertContains("crates/cose/Cargo.toml", "publish = true");
assertContains("crates/cose/Cargo.toml", 'include = [');
assertContains("crates/cose/Cargo.toml", '"/src/**/*.rs"');
assertContains("crates/cose/Cargo.toml", '"/README.md"');
assertContains("crates/cose/Cargo.toml", '"/LICENSE"');
assertContains("crates/cose/Cargo.toml", '"/NOTICE"');
assertContains("crates/cose/Cargo.toml", 'wire = [');
assertContains("crates/cose/Cargo.toml", '"dep:buffa"');
assertContains("crates/cose/Cargo.toml", '"dep:reallyme-cose-proto"');
assertContains("crates/cose/Cargo.toml", '"dep:serde"');
assertContains("crates/cose/Cargo.toml", '"dep:serde_json"');
assertContains(
  "Cargo.toml",
  'reallyme-codec = { version = "0.2.1", default-features = false, features = ["base64url", "cbor", "multikey"] }',
);
assertNotContains("Cargo.toml", 'path = "../codec');
assertContains("crates/proto/Cargo.toml", '"buffa/json"');
assertContains("crates/cose/src/lib.rs", 'reallyme-cose `wire` requires a runtime lane');
assertContains("Cargo.toml", 'buffa = { version = "0.9.0", features = ["json"] }');
assertContains(
  "Cargo.toml",
  `reallyme-cose-proto = { version = "${expectedVersion}", path = "crates/proto", default-features = false }`,
);
assertContains("Cargo.toml", 'serde = { version = "1.0", features = ["derive"] }');
assertContains("Cargo.toml", 'serde_json = "1.0"');
assertContains("Cargo.toml", 'allocation-counter = "0.8.1"');
assertContains("Cargo.toml", 'criterion = "0.8.2"');
assertContains("crates/cose/Cargo.toml", 'name = "operation_performance"');
assertTextPolicy({
  files: [
    {
      path: "Cargo.toml",
      required: ["overflow-checks = true"],
      forbidden: ["[patch.crates-io]"],
    },
    {
      path: ".cargo/config.toml",
      required: [
        'check-wasm = "check --workspace --target wasm32-unknown-unknown --no-default-features --features wasm"',
      ],
    },
  ],
});
assertContains("README.md", "actions/workflows/rust-ci.yml/badge.svg");
assertContains("README.md", "crates.io/crates/reallyme-cose");
assertContains("README.md", "Unsupported COSE Surface");
assertContains("README.md", "Resource Limits");
assertContains("README.md", "COSE-Layer Vector Audit");
assertContains("README.md", "The `wire` feature is intentionally non-additive");
assertContains("crates/cose/Cargo.toml", "[package.metadata.cargo_check_external_types]");
assertContains("crates/cose/Cargo.toml", '"crypto_core::algorithm::Algorithm"');
assertContains("crates/cose/Cargo.toml", '"reallyme_cose_proto::*"');
assertContains("crates/cose/Cargo.toml", '"zeroize::Zeroizing"');
assertNotContains("Cargo.toml", "getrandom02");
assertNotContains("crates/cose/Cargo.toml", "getrandom02");
assertContains("README.md", "cargo check-wasm");
assertContains("scripts/check-wasm-lane.mjs", "rustup target add wasm32-unknown-unknown");
assertContains(
  "scripts/release-readiness/operation-contract-routes.mjs",
  "export const OPERATION_CONTRACT_ROUTES",
);
assertContains(
  "scripts/release-readiness/operation-contract-routing.mjs",
  "collectOperationContractRoutingViolations",
);
assertContains(
  "scripts/release-readiness/operation-contract-routing.test.mjs",
  "current operation contract satisfies every routing invariant",
);
assertContains("fuzz/Cargo.toml", 'name = "wire"');
assertContains("fuzz/fuzz_targets/wire.rs", "execute_operation_proto");
assertContains("fuzz/fuzz_targets/wire.rs", "execute_operation_proto_json");
assertContains("fuzz/fuzz_targets/wire.rs", "decode_operation_response");
assertContains("fuzz/fuzz_targets/wire.rs", "decode_operation_response_for_request");
assertContains("fuzz/fuzz_targets/wire.rs", "Operation::KeyParse");
for (const migratedKeyOperation of [
  "Operation::KeyFromPublicBytes",
  "Operation::KeyFromPrivateBytes",
  "Operation::KeyToPublicBytes",
  "Operation::KeyToPrivateBytes",
  "Operation::KeyDerivePublicKid",
  "Operation::KeyToMultikey",
  "Operation::MultikeyToCoseKey",
]) {
  assertContains("fuzz/fuzz_targets/wire.rs", migratedKeyOperation);
}
for (const migratedSign1Operation of [
  "Operation::Sign1Create",
  "Operation::Sign1CreateDetached",
  "Operation::Sign1Verify",
  "Operation::Sign1VerifyDetached",
]) {
  assertContains("fuzz/fuzz_targets/wire.rs", migratedSign1Operation);
}
for (const migratedEncryptOperation of [
  "Operation::MlKemEncryptDirect",
  "Operation::MlKemEncryptKeyWrap",
  "Operation::MlKemDecrypt",
]) {
  assertContains("fuzz/fuzz_targets/wire.rs", migratedEncryptOperation);
}
assertContains("fuzz/README.md", "`wire`");
assertContains("fuzz/Cargo.toml", 'name = "cose_encrypt"');
assertContains("fuzz/fuzz_targets/cose_encrypt.rs", "cose_decrypt_ml_kem_with_external_aad");
assertContains("fuzz/README.md", "`cose_encrypt`");
assertContains(".github/workflows/fuzz.yml", "cose_encrypt");
assertContains("crates/cose/src/encrypt/types.rs", "pub enum CoseMlKemAlgorithm");
assertContains("crates/cose/src/encrypt/types.rs", "#[non_exhaustive]\npub struct CoseMlKemEncryptRequest");
assertContains("crates/cose/src/encrypt/types.rs", "pub(super) kem_algorithm: CoseMlKemAlgorithm");
assertContains("crates/cose/src/encrypt/types.rs", "pub const fn new(");
assertContains("crates/cose/src/zeroize_coset.rs", "pub(crate) fn zeroize_cose_encrypt");
assertContains("crates/cose/src/zeroize_coset.rs", "pub(crate) fn zeroize_cose_sign1");
for (const sensitiveCborEncoder of [
  "crates/cose/src/encrypt/codec.rs",
  "crates/cose/src/encrypt/kdf.rs",
  "crates/cose/src/key/convert.rs",
  "crates/cose/src/sign1/sign.rs",
]) {
  assertContains(sensitiveCborEncoder, "encode_cbor_value(");
  assertNotContains(sensitiveCborEncoder, "ciborium::ser::into_writer");
}
assertContains("crates/cose/src/sign1/sign.rs", "encode_protected_header(protected)?");
assertNotContains("crates/cose/src/sign1/sign.rs", "protected.clone().to_vec()");
assertContains("crates/cose/src/limits/validate.rs", "core::str::from_utf8(text)");
assertContains("README.md", "generated `PartialEq` is a schema");
assertContains(
  "README.md",
  "pair ML-KEM-512 with AES-128-GCM, ML-KEM-768 with",
);
assertContains(
  "README.md",
  "Every native Sign1 key resolver receives `(expected_algorithm, protected_kid)`.",
);
assertContains(
  "crates/cose/src/sign1/verify.rs",
  "public_key_resolver: impl Fn(Algorithm, &[u8])",
);
assertContains(
  "crates/cose/src/key/ec.rs",
  "validate_supplied_point(profile, public_key, raw_len, uncompressed_len)?",
);
assertContains(
  "crates/cose/src/key/validate_material.rs",
  "SECP256K1_VALIDATION_SIGNATURE_BYTES",
);
assertContains("crates/cose/src/key/convert.rs", "Result<Zeroizing<Vec<u8>>, CoseError>");
assertContains("crates/cose/src/key/parse.rs", "pub(crate) fn parse_cose_key(");
assertContains("crates/cose/src/key/parse.rs", "fn decode_owned_cose_key(");
assertContains(
  "crates/cose/src/key/parse.rs",
  "parse_cose_key(CoseKeyParseInput::new(bytes))",
);
assertContains("crates/cose/src/key/mod.rs", "pub use parse::cose_key_from_slice;");
assertNotContains("crates/cose/src/key/convert.rs", "pub fn cose_key_from_slice");
assertContains(
  "crates/cose/src/operation_contract/key/parse.rs",
  "parse_cose_key(CoseKeyParseInput::new(&encoded_key))",
);
assertNotContains("crates/cose/src/operation_contract/key/parse.rs", "cose_key_from_slice");
assertContains(
  "crates/cose/src/operation_contract/execute.rs",
  "super::key::parse::result(*request)",
);
for (const semanticRoute of [
  "construct_cose_key_from_public(CoseKeyFromPublicBytesInput::new(",
  "construct_cose_key_from_private(CoseKeyFromPrivateBytesInput::new(",
  "extract_cose_key_public(CoseKeyRefInput::new(",
  "extract_cose_key_private(CoseKeyRefInput::new(",
]) {
  assertContains("crates/cose/src/key/convert.rs", semanticRoute);
}
assertContains(
  "crates/cose/src/key/derive_kid.rs",
  "derive_cose_key_public_kid(CoseKeyRefInput::new(key))",
);
assertContains(
  "crates/cose/src/multikey/convert.rs",
  "convert_cose_key_to_multikey(CoseKeyRefInput::new(key))",
);
assertContains(
  "crates/cose/src/multikey/convert.rs",
  "convert_multikey_to_cose_key(MultikeyInput::new(multikey))",
);
for (const semanticCall of [
  "construct_cose_key_from_public(",
  "construct_cose_key_from_private(",
  "extract_cose_key_public(",
  "extract_cose_key_private(",
  "derive_cose_key_public_kid(",
  "convert_cose_key_to_multikey(",
  "convert_multikey_to_cose_key(",
]) {
  assertContains("crates/cose/src/operation_contract/key/convert.rs", semanticCall);
}
const keyContractAdapter = readText("crates/cose/src/operation_contract/key/convert.rs");
for (const bypassedFacade of [
  "cose_key_from_public_bytes",
  "cose_key_from_private_bytes",
  "cose_key_to_public_bytes",
  "cose_key_to_private_bytes",
  "derive_kid_from_cose_key_public",
  "cose_key_to_multikey",
  "multikey_to_cose_key",
]) {
  // Match a complete Rust identifier so semantic names such as
  // `convert_cose_key_to_multikey` do not create false policy failures.
  if (new RegExp(`\\b${bypassedFacade}\\s*\\(`, "u").test(keyContractAdapter)) {
    fail(
      `crates/cose/src/operation_contract/key/convert.rs must not call convenience facade ${bypassedFacade}`,
    );
  }
}
for (const contractRoute of [
  "super::key::convert::from_public_bytes_result(*request)",
  "super::key::convert::from_private_bytes_result(*request)",
  "super::key::convert::to_public_bytes_result(*request)",
  "super::key::convert::to_private_bytes_result(*request)",
  "super::key::convert::derive_public_kid_result(*request)",
  "super::key::convert::to_multikey_result(*request)",
  "super::key::convert::multikey_to_key_result(*request)",
]) {
  assertContains("crates/cose/src/operation_contract/execute.rs", contractRoute);
}
assertContains(
  "crates/cose/src/sign1/sign.rs",
  "create_cose_sign1(CoseSign1CreateInput::new(",
);
assertContains(
  "crates/cose/src/sign1/sign.rs",
  "create_detached_cose_sign1(CoseSign1CreateInput::new(",
);
assertContains(
  "crates/cose/src/sign1/verify.rs",
  "verify_cose_sign1(",
);
assertContains(
  "crates/cose/src/sign1/verify.rs",
  "verify_detached_cose_sign1(",
);
for (const semanticCall of [
  "create_cose_sign1(",
  "create_detached_cose_sign1(",
]) {
  assertContains("crates/cose/src/operation_contract/sign1/create.rs", semanticCall);
}
for (const semanticCall of [
  "verify_cose_sign1(",
  "verify_detached_cose_sign1(",
]) {
  assertContains("crates/cose/src/operation_contract/sign1/verify.rs", semanticCall);
}
for (const [adapter, bypassedFacades] of [
  [
    "crates/cose/src/operation_contract/sign1/create.rs",
    [
      "cose_sign1_with_options_and_external_aad",
      "cose_sign1_detached_with_options_and_external_aad",
    ],
  ],
  [
    "crates/cose/src/operation_contract/sign1/verify.rs",
    [
      "cose_verify1_with_policy_and_external_aad",
      "cose_verify1_detached_with_policy_and_external_aad",
    ],
  ],
]) {
  const adapterSource = readText(adapter);
  for (const bypassedFacade of bypassedFacades) {
    if (new RegExp(`\\b${bypassedFacade}\\s*\\(`, "u").test(adapterSource)) {
      fail(`${adapter} must not call convenience facade ${bypassedFacade}`);
    }
  }
}
for (const contractRoute of [
  "super::sign1::create::attached_result(*request)",
  "super::sign1::create::detached_result(*request)",
  "super::sign1::verify::attached_result(*request)",
  "super::sign1::verify::detached_result(*request)",
]) {
  assertContains("crates/cose/src/operation_contract/execute.rs", contractRoute);
}
assertContains(
  "crates/cose/src/encrypt/create.rs",
  "encrypt_cose_ml_kem_direct(CoseMlKemEncryptInput::new(",
);
assertContains(
  "crates/cose/src/encrypt/create.rs",
  "encrypt_cose_ml_kem_key_wrap(CoseMlKemEncryptInput::new(",
);
assertContains(
  "crates/cose/src/encrypt/decrypt.rs",
  "decrypt_cose_ml_kem(CoseMlKemDecryptInput::new(",
);
assertContains(
  "crates/cose/src/operation_contract/encrypt/decrypt.rs",
  "decrypt_cose_ml_kem(",
);
for (const [adapter, bypassedFacades] of [
  [
    "crates/cose/src/operation_contract/encrypt/create.rs",
    [
      "cose_encrypt_ml_kem_direct_with_external_aad",
      "cose_encrypt_ml_kem_key_wrap_with_external_aad",
    ],
  ],
  [
    "crates/cose/src/operation_contract/encrypt/decrypt.rs",
    ["cose_decrypt_ml_kem_with_external_aad"],
  ],
]) {
  const adapterSource = readText(adapter);
  for (const bypassedFacade of bypassedFacades) {
    if (new RegExp(`\\b${bypassedFacade}\\s*\\(`, "u").test(adapterSource)) {
      fail(`${adapter} must not call convenience facade ${bypassedFacade}`);
    }
  }
}
for (const contractRoute of [
  "super::encrypt::create::direct_result(*request)",
  "super::encrypt::create::key_wrap_result(*request)",
  "super::encrypt::decrypt::result(*request)",
]) {
  assertContains("crates/cose/src/operation_contract/execute.rs", contractRoute);
}
assertNotContains("crates/cose/src/wire.rs", "fn boundary_error_from_encrypt_error(");
assertNotContains("crates/cose/src/wire.rs", "fn dispatch_operation(");
assertContains("crates/cose/src/operation_contract/execute.rs", "fn dispatch_operation(");
assertContains("crates/cose/src/wire.rs", "crate::operation_contract::execute::execute_proto(request_bytes)");
assertContains(
  "crates/cose/src/wire.rs",
  "crate::operation_contract::execute::execute_proto_json(request_json)",
);
assertOperationContractRouting({ readText, fail });
for (const [family, generatedResults] of [
  ["key", ["CoseKeyBytesResult", "CoseMultikeyResult"]],
  ["sign1", ["CoseSign1CreateResult", "CoseSign1VerifyResult"]],
  ["encrypt", ["CoseMlKemEncryptResult", "CoseMlKemDecryptResult"]],
]) {
  const modulePath = `crates/cose/src/operation_contract/${family}/mod.rs`;
  const resultPath = `crates/cose/src/operation_contract/${family}/result.rs`;
  assertContains(modulePath, "pub(crate) mod result;");
  assertContains(resultPath, "CoseOperationResult {");
  for (const generatedResult of generatedResults) {
    assertContains(resultPath, `${generatedResult} {`);
    assertNotContains("crates/cose/src/wire.rs", `${generatedResult} {`);
  }
}
for (const adapterPath of [
  "crates/cose/src/operation_contract/key/parse.rs",
  "crates/cose/src/operation_contract/key/convert.rs",
  "crates/cose/src/operation_contract/sign1/create.rs",
  "crates/cose/src/operation_contract/sign1/verify.rs",
  "crates/cose/src/operation_contract/encrypt/create.rs",
  "crates/cose/src/operation_contract/encrypt/decrypt.rs",
]) {
  assertContains(adapterPath, "result::");
}
for (const removedWireResultHelper of [
  "encode_key_bytes_result",
  "encode_multikey_result",
  "encode_sign1_create_result",
  "encode_sign1_verify_result",
  "encode_ml_kem_encrypt_result",
  "encode_ml_kem_decrypt_result",
  "signature_algorithm_to_proto",
  "content_algorithm_to_proto",
  "ml_kem_algorithm_to_proto",
  "ml_kem_mode_to_proto",
  "boundary_error_from_cose_error",
]) {
  assertNotContains("crates/cose/src/wire.rs", removedWireResultHelper);
}
assertContains("crates/cose/src/zeroize_coset.rs", "struct SensitiveCborValue");
assertContains("crates/cose/src/key/owned.rs", "fn zeroize_cose_key");
assertContains("crates/cose/src/key/owned.rs", "core::mem::take(&mut key.key_ops)");
assertContains("vectors/manifest.json", "reallyme.cose.conformance.vector_manifest.v1");
assertContains("vectors/manifest.json", "cose-encrypt-ml-kem");
assertContains("vectors/manifest.json", "cose-sign1-pq");
assertContains("vectors/manifest.json", "cose-key-pq");
assertContains("vectors/manifest.json", '"sha256"');
assertContains("vectors/cose-sign1-pq.json", "ML-DSA-44");
assertContains("vectors/cose-sign1-pq.json", "ML-DSA-65");
assertContains("vectors/cose-sign1-pq.json", "ML-DSA-87");
assertContains("vectors/cose-sign1-pq.json", "cose-sign1-ml-dsa-44-tampered-signature");
assertContains("vectors/cose-sign1-pq.json", "cose-sign1-ml-dsa-44-truncated-signature");
assertContains("vectors/cose-sign1-pq.json", "cose-sign1-ml-dsa-44-extended-signature");
assertContains("vectors/cose-sign1.json", "cose-sign1-ed25519-node-openssl");
assertContains("vectors/cose-sign1.json", "node_open_ssl_rfc8032");
assertContains("vectors/cose-key-pq.json", "ML-KEM-512");
assertContains("vectors/cose-key-pq.json", "ML-KEM-768");
assertContains("vectors/cose-key-pq.json", "ML-KEM-1024");
assertContains(
  "vectors/cose-encrypt-ml-kem.json",
  "reallyme.cose.ml_kem_encrypt.vectors.v1",
);
assertContains("tools/vector-audit/Cargo.toml", 'name = "reallyme-cose-vector-audit"');
assertContains("tools/vector-audit/src/ml_kem_encrypt.rs", "Kmac256");
assertContains("tools/vector-audit/src/ml_kem_encrypt.rs", "unwrap_key");
assertContains("tools/vector-goldens/Cargo.toml", 'name = "reallyme-cose-vector-goldens"');
assertContains("tools/vector-goldens/src/ml_kem_encrypt.rs", "encapsulate_deterministic");
assertContains("tools/vector-audit/src/pq.rs", "verify_ml_dsa");
assertContains("tools/vector-goldens/src/pq.rs", "add_ml_dsa");
assertContains("buf.yaml", "modules:");
assertContains("buf.yaml", "- path: crates/proto/proto");
assertNotContains("buf.yaml", "except:");
assertNotContains("buf.yaml", "FIELD_NO_DELETE");
assertNotContains("buf.yaml", "MESSAGE_NO_DELETE");
assertContains("buf.gen.yaml", "protoc-gen-buffa");
assertContains("buf.gen.yaml", "protoc-gen-buffa-packaging");
assertContains("buf.gen.yaml", "views=true");
assertContains("crates/proto/Cargo.toml", `name = "${expectedProtoPackageName}"`);
assertContains("crates/proto/Cargo.toml", `version = "${expectedVersion}"`);
assertContains("crates/proto/Cargo.toml", "publish = true");
assertContains("crates/proto/Cargo.toml", '"/proto/**/*.proto"');
assertContains("crates/proto/Cargo.toml", 'default = ["generated"]');
assertContains("crates/proto/Cargo.toml", 'zeroize = { workspace = true, optional = true }');
assertContains("crates/proto/src/generated.rs", "COSE_PROTO_PACKAGE");
assertContains("crates/proto/src/generated/buffa/mod.rs", "@generated by buffa-codegen");
assertContains("scripts/harden-generated-cose-proto.mjs", "Zeroize::zeroize(&mut self.private_key)");
assertContains("scripts/harden-generated-cose-proto.mjs", "redactDebugBytes");
assertContains("scripts/harden-generated-cose-proto.mjs", "__reallyme_zeroize_unknown_fields");
assertContains("scripts/harden-generated-cose-proto.mjs", '"cose_key"');
assertContains("scripts/harden-generated-cose-proto.mjs", '"key_bytes"');
assertContains("scripts/harden-generated-cose-proto.mjs", '"external_aad"');
assertContains("scripts/harden-generated-cose-proto.mjs", '"expected_kid"');
assertContains("scripts/harden-generated-cose-proto.mjs", "deny_unknown_fields");
assertContains("scripts/harden-generated-cose-proto.mjs", "unknown field");
assertContains("scripts/harden-generated-cose-proto.mjs", '"--check-idempotent"');
assertContains("scripts/harden-generated-cose-proto.mjs", '["CoseOperationRequest", []]');
assertReallyMeProtobufReleasePolicy({
  generatedFreshnessMode,
  buffaVersion: "0.9.0",
  workflowMode: "delegated",
  generatedFreshnessStepRun:
    "node .release-readiness/scripts/run-consumer-check.mjs --generated-freshness",
  installBufRun: verifiedBufInstallCommand,
  hardeningPolicy: {
    hardeningScript: "scripts/harden-generated-cose-proto.mjs",
    protoSchema: "crates/proto/proto/reallyme/cose/v1/cose.proto",
    generatedRust: "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
    generatedView: "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.__view.rs",
    protoCargo: "crates/proto/Cargo.toml",
    requiredScriptNeedles: [
      "Zeroize::zeroize(&mut self.private_key)",
      "redactDebugBytes",
      "__reallyme_zeroize_unknown_fields",
      '"cose_key"',
      '"key_bytes"',
      '"external_aad"',
      '"expected_kid"',
    ],
    requiredCargoNeedles: ['"buffa/json"'],
    // Every bytes/string field is deliberately classified. "Sensitive" here
    // means the generated owner must redact and wipe the value; it includes
    // public keys and Multikey strings because they are persistent identity
    // correlators even when they are not cryptographic secrets.
    scalarFieldClassifications: [
      { message: "CoseMlKemEncryptRequest", field: "recipient_public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseMlKemEncryptRequest", field: "recipient_kid", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseMlKemEncryptRequest", field: "plaintext", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseMlKemEncryptRequest", field: "external_aad", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseMlKemEncryptRequest", field: "supp_priv_info", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseMlKemEncryptResult", field: "cose_encrypt", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseMlKemDecryptRequest", field: "cose_encrypt", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseMlKemDecryptRequest", field: "recipient_private_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseMlKemDecryptRequest", field: "expected_recipient_kid", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseMlKemDecryptRequest", field: "external_aad", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseMlKemDecryptRequest", field: "supp_priv_info", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseMlKemDecryptResult", field: "plaintext", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseMlKemDecryptResult", field: "recipient_kid", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1CreateRequest", field: "payload", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1CreateRequest", field: "private_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1CreateRequest", field: "kid", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1CreateRequest", field: "external_aad", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1CreateDetachedRequest", field: "payload", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1CreateDetachedRequest", field: "private_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1CreateDetachedRequest", field: "kid", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1CreateDetachedRequest", field: "external_aad", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1CreateResult", field: "cose_sign1", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1VerifyRequest", field: "cose_sign1", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1VerifyRequest", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1VerifyRequest", field: "external_aad", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1VerifyRequest", field: "expected_kid", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1VerifyDetachedRequest", field: "cose_sign1", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1VerifyDetachedRequest", field: "payload", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1VerifyDetachedRequest", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1VerifyDetachedRequest", field: "external_aad", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1VerifyDetachedRequest", field: "expected_kid", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1VerifyResult", field: "payload", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseSign1VerifyResult", field: "kid", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseKeyFromPublicBytesRequest", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseKeyFromPrivateBytesRequest", field: "private_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseKeyFromPrivateBytesRequest", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseKeyBytesRequest", field: "cose_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseKeyBytesResult", field: "key_bytes", kind: "bytes", sensitivity: "sensitive" },
      { message: "CoseMultikeyToCoseKeyRequest", field: "multikey", kind: "string", sensitivity: "sensitive" },
      { message: "CoseMultikeyResult", field: "multikey", kind: "string", sensitivity: "sensitive" },
    ],
    requiredGeneratedNeedles: [
      "fn __reallyme_zeroize_unknown_fields(",
      '.field("private_key", &"<redacted>")',
      '.field("payload", &"<redacted>")',
      '.field("cose_key", &"<redacted>")',
      '.field("key_bytes", &"<redacted>")',
      "::zeroize::Zeroize::zeroize(&mut self.private_key);",
    ],
    forbiddenGeneratedNeedles: [
      "::buffa::alloc::format!(",
      '.field("private_key", &self.private_key)',
      '.field("payload", &self.payload)',
      '.field("cose_key", &self.cose_key)',
    ],
    requiredViewNeedles: [
      'formatter.write_str("CoseSign1CreateRequestView(<redacted>)")',
      'formatter.write_str("CoseMlKemDecryptResultView(<redacted>)")',
      'formatter.write_str("CoseSign1CreateRequestOwnedView(<redacted>)")',
      'formatter.write_str("CoseMlKemDecryptResultOwnedView(<redacted>)")',
    ],
  },
  generatedFreshness: {
    generatedPaths: ["crates/proto/src/generated"],
    commands: [
      ["buf", ["lint"]],
      ["buf", ["generate"]],
      ["node", ["scripts/harden-generated-cose-proto.mjs"]],
      ["node", ["scripts/harden-generated-cose-proto.mjs", "--check-idempotent"]],
      ["cargo", ["fmt", "--package", expectedProtoPackageName]],
    ],
  },
});
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  "impl ::core::ops::Drop for CoseSign1CreateRequest",
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  "impl ::core::ops::Drop for CoseSign1CreateDetachedRequest",
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  "impl ::core::ops::Drop for CoseKeyFromPrivateBytesRequest",
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  '.field("private_key", &"<redacted>")',
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  '.field("payload", &"<redacted>")',
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  '.field("cose_key", &"<redacted>")',
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  '.field("key_bytes", &"<redacted>")',
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  "::zeroize::Zeroize::zeroize(&mut self.private_key);",
);
assertNotContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  '.field("private_key", &self.private_key)',
);
assertNotContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  '.field("payload", &self.payload)',
);
assertNotContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  '.field("cose_key", &self.cose_key)',
);
assertNotContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  '.field("key_bytes", &self.key_bytes)',
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.mod.rs",
  "__view",
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.__view.rs",
  'formatter.write_str("CoseSign1CreateRequestView(<redacted>)")',
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.__view.rs",
  'formatter.write_str("CoseMlKemDecryptResultView(<redacted>)")',
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.__view.rs",
  'formatter.write_str("CoseSign1CreateRequestOwnedView(<redacted>)")',
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.__view.rs",
  'formatter.write_str("CoseMlKemDecryptResultOwnedView(<redacted>)")',
);
assertContains("crates/cose/src/wire.rs", "reallyme_cose_proto::generated::proto::reallyme::cose::v1");
assertContains("crates/cose/src/wire.rs", "DecodeOptions::new()");
assertContains("crates/cose/src/wire.rs", "const COSE_PROTO_UNKNOWN_FIELD_LIMIT: usize = 0;");
assertContains("crates/cose/src/wire.rs", ".with_unknown_field_limit(COSE_PROTO_UNKNOWN_FIELD_LIMIT)");
assertNotContains("crates/cose/src/wire.rs", "prost");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "package reallyme.cose.v1;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", 'option swift_prefix = "ReallyMeProto";');
assertProtoContract("crates/proto/proto/reallyme/cose/v1/cose.proto");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseError");
assertNotContains("crates/proto/proto/reallyme/cose/v1/cose.proto", 'reserved "sign1", "key", "multikey";');
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "CosePrimitiveError primitive = 1;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "CoseProviderError provider = 2;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "CoseBackendError backend = 3;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CosePrimitiveError");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseProviderError");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseBackendError");
assertNotContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseSign1Error");
assertNotContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseKeyError");
assertNotContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseMultikeyError");
assertNotContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "enum CoseOperation");
assertNotContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "CoseProtoResultEnvelope");
assertNotContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "CoseProtoResultStatus");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseOperationRequest");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseOperationResponseV2");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseOperationResult");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "CoseOperationResult result = 1;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "CoseError error = 2;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "reserved 1 to 15;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "CoseSign1CreateRequest sign1_create = 1000;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "CoseMultikeyToCoseKeyRequest multikey_to_cose_key = 2007;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "CoseMlKemDecryptRequest ml_kem_decrypt = 3002;");
for (const versionTwoResultField of [
  "CoseSign1CreateResult sign1_create = 1000;",
  "CoseSign1CreateResult sign1_create_detached = 1001;",
  "CoseSign1VerifyResult sign1_verify = 1002;",
  "CoseSign1VerifyResult sign1_verify_detached = 1003;",
  "CoseKeyBytesResult key_from_public_bytes = 2000;",
  "CoseKeyBytesResult key_from_private_bytes = 2001;",
  "CoseKeyBytesResult key_parse = 2002;",
  "CoseKeyBytesResult key_to_public_bytes = 2003;",
  "CoseKeyBytesResult key_to_private_bytes = 2004;",
  "CoseKeyBytesResult key_derive_public_kid = 2005;",
  "CoseMultikeyResult key_to_multikey = 2006;",
  "CoseKeyBytesResult multikey_to_cose_key = 2007;",
  "CoseMlKemEncryptResult ml_kem_encrypt_direct = 3000;",
  "CoseMlKemEncryptResult ml_kem_encrypt_key_wrap = 3001;",
  "CoseMlKemDecryptResult ml_kem_decrypt = 3002;",
]) {
  assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", versionTwoResultField);
}
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "enum CoseSignatureAlgorithm");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "enum CoseKeyAgreementAlgorithm");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "enum CoseKemAlgorithm");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseAlgorithmIdentifier");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "COSE_SIGNATURE_ALGORITHM_ED25519 = 100;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "COSE_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 = 200;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "COSE_SIGNATURE_ALGORITHM_ML_DSA_44 = 1000;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "COSE_KEY_AGREEMENT_ALGORITHM_X25519 = 100;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "COSE_KEM_ALGORITHM_ML_KEM_512 = 1000;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "COSE_KEM_ALGORITHM_X_WING_768 = 1100;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "COSE_CONTENT_ENCRYPTION_ALGORITHM_AES_128_GCM = 100;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "CoseSignatureAlgorithm algorithm = 1;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "CoseKemAlgorithm kem_algorithm = 1;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "CoseAlgorithmIdentifier algorithm = 1;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseSign1CreateRequest");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseSign1VerifyResult");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseKeyBytesResult");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "SENSITIVE: raw private key bytes");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "SENSITIVE: payload bytes");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "SENSITIVE: encoded COSE_Key bytes");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "SENSITIVE: operation-specific bytes");
assertContains("crates/cose/src/wire.rs", "pub fn execute_operation_proto(");
assertContains("crates/cose/src/wire.rs", "pub fn execute_operation_proto_json(");
assertContains("crates/cose/src/wire.rs", "pub fn decode_operation_response(");
assertContains("crates/cose/src/wire.rs", "pub fn decode_operation_response_for_request(");
assertNotContains("crates/cose/src/wire.rs", "CoseProtoOutput");
assertNotContains("crates/cose/src/wire.rs", "CoseProtoStatus");
assertNotContains("crates/cose/src/wire.rs", "CoseProtoResultEnvelope");
assertContains("crates/cose/src/wire.rs", "pub fn decode_cose_error(");
assertNotContains("crates/cose/src/wire.rs", "pub fn process_operation_output(");
assertNotContains("crates/cose/src/wire.rs", "pub struct CoseWireError");
assertNotContains("crates/cose/src/wire.rs", "pub enum CoseWireErrorConstructionError");
assertNotContains("crates/cose/src/wire.rs", "pub fn try_new(");
assertContains("crates/cose/src/wire.rs", "fn reason_is_valid_for_branch(");
assertNotContains("crates/cose/src/wire.rs", "pub type CoseWireResult");
assertContains("crates/cose/src/operation_contract/mod.rs", "pub(crate) mod response_v2;");
assertContains("crates/cose/src/operation_contract/response_v2.rs", "fn result_matches_request(");
assertContains("crates/cose/src/operation_contract/response_v2.rs", "CoseOperationResultBranch::MlKemDecrypt");
assertContains("scripts/harden-generated-cose-proto.mjs", '["CoseOperationResponseV2", []]');
assertContains("scripts/harden-generated-cose-proto.mjs", '["CoseOperationResult", []]');
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  "impl ::core::ops::Drop for CoseOperationResponseV2",
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  "impl ::core::ops::Drop for CoseOperationResult",
);
assertContains("crates/cose/src/error.rs", "#[non_exhaustive]");
assertContains("crates/cose/src/key/owned.rs", "#[must_use]\npub struct CoseKey");
assertContains(
  "crates/cose/src/key/derive_kid.rs",
  "Result<Zeroizing<Vec<u8>>, CoseError>",
);
assertContains(
  "crates/cose/src/multikey/convert.rs",
  "Result<Zeroizing<String>, CoseError>",
);
assertContains("crates/cose/src/sign1/provider.rs", "pub trait CoseSigner");
assertContains("crates/cose/src/sign1/provider.rs", "pub enum CoseSignerError");
assertContains("crates/cose/src/sign1/sign.rs", "pub fn cose_sign1_with_signer(");
assertContains("crates/cose/src/sign1/sign.rs", "pub fn cose_sign1_detached_with_signer(");
assertContains("crates/cose/tests/cose_suite/platform_signer_tests.rs", "CoseSignerError::Unavailable");
assertContains("crates/cose/tests/cose_suite/concurrency_tests.rs", "thread::scope");
for (const allocationLimit of [
  "SIGN1_PEAK_ALLOCATION_LIMIT",
  "KEY_PEAK_ALLOCATION_LIMIT",
  "MULTIKEY_PEAK_ALLOCATION_LIMIT",
  "DECRYPT_PEAK_ALLOCATION_LIMIT",
]) {
  assertContains("crates/cose/benches/operation_performance.rs", allocationLimit);
}
assertContains("crates/cose/src/policy/validate.rs", "#[must_use]\n#[derive(Debug, Clone)]\npub struct CosePolicy");
assertContains("crates/cose/src/policy/validate.rs", "require_kid: bool");
assertContains("crates/cose/src/policy/validate.rs", "pub fn with_require_kid");
assertNotContains("crates/cose/src/policy/validate.rs", "pub require_kid: bool");
assertNotContains("crates/cose/src/policy/validate.rs", "pub allowed_algs: Vec<Algorithm>");
assertNotContains("crates/cose/src/policy/validate.rs", "pub max_cose_sign1_bytes: usize");
assertContains("crates/cose/src/sign1/sign.rs", "#[must_use]\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct CoseSign1EncodeOptions");
assertContains("crates/cose/src/sign1/sign.rs", "tag: bool");
assertContains("crates/cose/src/sign1/sign.rs", "pub const fn tagged()");
assertNotContains("crates/cose/src/sign1/sign.rs", "pub tag: bool");
assertNotContains("crates/cose/src/sign1/sign.rs", "pub max_cose_sign1_bytes: usize");
assertContains("crates/cose/src/sign1/verify.rs", "#[must_use]\n#[non_exhaustive]\npub struct VerifiedCoseSign1");
assertNotContains("crates/cose/src/wire.rs", "pub type CoseWireBytes = Zeroizing<Vec<u8>>;");
assertNotContains("crates/cose/src/wire.rs", "pub fn encode_protobuf<M: Message>");
assertContains("crates/cose/src/wire.rs", "Zeroizing::new(message.encode_to_vec())");
assertContains("crates/cose/src/wire.rs", "COSE_PROTO_PACKAGE");
assertContains("crates/cose/src/operation_contract/input.rs", "if limit > MAX_COSE_PROTO_MESSAGE_BYTES");
assertNotContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  "CoseSign1Error",
);
assertNotContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  "CoseKeyError",
);
assertNotContains(
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
  "CoseMultikeyError",
);
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "enum CoseErrorReason");
assertContains(
  "crates/proto/proto/reallyme/cose/v1/cose.proto",
  "COSE_ERROR_REASON_COMMON_CBOR = 100;",
);
assertContains(
  "crates/proto/proto/reallyme/cose/v1/cose.proto",
  "COSE_ERROR_REASON_COMMON_MALFORMED_PROTOBUF = 120;",
);
assertContains(
  "crates/proto/proto/reallyme/cose/v1/cose.proto",
  "COSE_ERROR_REASON_SIGN1_KID_KEY_MISMATCH = 400;",
);
assertContains(
  "crates/proto/proto/reallyme/cose/v1/cose.proto",
  "COSE_ERROR_REASON_SIGN1_MISSING_PAYLOAD = 401;",
);
assertContains(
  "crates/proto/proto/reallyme/cose/v1/cose.proto",
  "COSE_ERROR_REASON_KEY_MISSING_KEY_MATERIAL = 500;",
);
assertContains(
  "crates/proto/proto/reallyme/cose/v1/cose.proto",
  "COSE_ERROR_REASON_MULTIKEY_INVALID_MULTIKEY = 600;",
);
assertContains(
  "crates/proto/proto/reallyme/cose/v1/cose.proto",
  "COSE_ERROR_REASON_SIGN1_INVALID_SIGNATURE_ENCODING = 422;",
);
assertContains(
  "crates/proto/proto/reallyme/cose/v1/cose.proto",
  "COSE_ERROR_REASON_ENCRYPT_MISSING_KID = 731;",
);
assertContains(
  "crates/proto/proto/reallyme/cose/v1/cose.proto",
  "COSE_ERROR_REASON_ENCRYPT_UNPROTECTED_HEADER_NOT_ALLOWED = 740;",
);
assertContains("crates/cose/src/failure.rs", "pub(crate) fn from_encrypt_error(");
assertContains("crates/cose/src/failure.rs", "CoseFailureReason::EncryptMissingKid");
assertContains(
  "crates/cose/src/failure.rs",
  "CoseFailureReason::EncryptUnprotectedHeaderNotAllowed",
);
assertContains(".github/workflows/rust-ci.yml", "paths-ignore:");
assertContains(".github/workflows/rust-ci.yml", "tools/vector-goldens/Cargo.toml");
assertContains(".github/workflows/rust-ci.yml", "--features native,wire");
assertContains(".github/workflows/rust-ci.yml", "--features wasm,wire --target wasm32-unknown-unknown");
assertContains(".github/workflows/rust-ci.yml", "cargo nextest run --release --locked --workspace --all-features");
assertContains(".github/workflows/rust-ci.yml", "wasm-pack test --node crates/cose");
assertContains(".github/workflows/rust-ci.yml", "CARGO_CHECK_EXTERNAL_TYPES_VERSION: 0.5.0");
assertContains(".github/workflows/rust-ci.yml", "EXTERNAL_TYPES_NIGHTLY: nightly-2026-03-20");
assertContains(".github/workflows/rust-ci.yml", "check-external-types --manifest-path crates/cose/Cargo.toml --all-features");
assertContains(".github/workflows/fuzz.yml", "paths-ignore:");
assertContains(".github/workflows/crates-release.yml", "CARGO_REGISTRY_TOKEN");
assertContains(".github/workflows/crates-release.yml", "name: Crates.io Release");
assertContains(
  ".github/workflows/crates-release.yml",
  "run-name: Crates.io release @ ${{ github.sha }}",
);
assertContains(
  ".github/workflows/crates-release.yml",
  "group: crates-release-${{ github.sha }}",
);
assertContains(
  ".github/workflows/crates-release.yml",
  "group: crates-release-${{ needs.verify-preflight.outputs.release_version }}-${{ needs.verify-preflight.outputs.release_sha }}",
);
assertContains(".github/workflows/crates-release.yml", "if: github.ref == 'refs/heads/main'");
assertNotContains(".github/workflows/crates-release.yml", "environment:");
assertContains(".github/workflows/crates-release.yml", "workflow_dispatch:");
assertNotContains(".github/workflows/crates-release.yml", "${{ inputs.");
assertContains(".github/workflows/crates-release.yml", "verify-preflight:");
assertContains(".github/workflows/crates-release.yml", "actions: read");
assertContains(".github/workflows/crates-release.yml", "runs-on: ubuntu-24.04");
assertNotContains(".github/workflows/crates-release.yml", "runs-on: ubuntu-latest");
assertContains(
  ".github/workflows/crates-release.yml",
  "node scripts/verify_release_attestation.mjs",
);
assertContains(
  ".github/workflows/crates-release.yml",
  "uses: actions/download-artifact@",
);
assertContains(
  ".github/workflows/crates-release.yml",
  "reallyme-cose-crates-preflight-${{ steps.verify-source.outputs.release_version }}-${{ steps.verify-source.outputs.release_sha }}",
);
assertContains(".github/workflows/crates-release.yml", "uses: actions/checkout@");
assertContains(".github/workflows/crates-release.yml", "uses: actions/setup-node@");
assertContains(".github/workflows/crates-release.yml", "uses: Swatinem/rust-cache@");
assertContains(".github/workflows/crates-release.yml", "node-version: '24'");
assertContains(
  ".github/workflows/crates-release.yml",
  "ref: ${{ github.sha }}",
);
assertContains(".github/workflows/crates-release.yml", "persist-credentials: false");
assertContains(
  ".github/workflows/crates-release.yml",
  "node scripts/verify_release_source.mjs",
);
assertContains(
  ".github/workflows/crates-release.yml",
  "RELEASE_SOURCE_DERIVE_VERSION: '1'",
);
assertContains(
  ".github/workflows/crates-release.yml",
  "RELEASE_ATTESTATION_RESOLVE_ONLY: '1'",
);
assertContains(
  ".github/workflows/crates-release.yml",
  "run-id: ${{ steps.resolve-attestation.outputs.preflight_run_id }}",
);
assertNotContains(".github/workflows/crates-release.yml", "dry-run:");
assertNotContains(".github/workflows/crates-release.yml", "node scripts/publish_crates_in_order.mjs inspect");
assertNotContains(".github/workflows/crates-release.yml", "buf generate");
assertNotContains(".github/workflows/crates-release.yml", "cargo nextest run");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "node scripts/run_pinned_release_readiness.mjs --release-packages",
);
assertContains(
  ".github/workflows/protobuf-ci.yml",
  "node .release-readiness/scripts/run-consumer-check.mjs --generated-freshness",
);
assertContains(
  ".github/workflows/rust-ci.yml",
  "node .release-readiness/scripts/run-consumer-check.mjs --policy-only",
);
for (const releaseReadinessWorkflow of [
  ".github/workflows/protobuf-ci.yml",
  ".github/workflows/rust-ci.yml",
]) {
  assertContains(releaseReadinessWorkflow, "repository: reallyme/release-readiness");
  assertContains(
    releaseReadinessWorkflow,
    "ref: f27973caf9d3a12847cac4032c361f5f553c97e9",
  );
  assertContains(releaseReadinessWorkflow, "persist-credentials: false");
}
assertContains(".github/workflows/crates-release.yml", "node scripts/publish_crates_in_order.mjs publish");
assertContains(".github/workflows/crates-release.yml", 'tag="reallyme-cose-v${RELEASE_VERSION}"');
assertContains(
  ".github/workflows/crates-release.yml",
  'if resolved_commit="$(gh api "repos/$GITHUB_REPOSITORY/commits/$tag" --jq \'.sha\' 2>/dev/null)"; then',
);
assertNotContains(
  ".github/workflows/crates-release.yml",
  '2>/dev/null || true)',
);
assertContains(".github/workflows/crates-release.yml", 'gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs"');
assertNotContains(".github/workflows/crates-release.yml", "git push");
assertContains(".github/workflows/crates-release.yml", "gh release create");
assertContains(".github/workflows/crates-release.yml", "RELEASE_TAG: ${{ steps.release-tag.outputs.tag }}");
assertNotContains(
  ".github/workflows/crates-release.yml",
  'tag="${{ steps.release-tag.outputs.tag }}"',
);
assertContains("scripts/publish_crates_in_order.mjs", "Publish order");
assertContains("scripts/publish_crates_in_order.mjs", "workspace publish dependency cycle");
assertContains("scripts/publish_crates_in_order.mjs", "REQUIRED_PUBLISH_ORDER_EDGES");
assertContains("scripts/publish_crates_in_order.mjs", "reallyme-cose-proto");
assertContains("scripts/publish_crates_in_order.mjs", "checkPathDependencyVersions();");
assertContains("scripts/publish_crates_in_order.mjs", "checkRequiredPublishOrderEdges();");
assertContains("scripts/publish_crates_in_order.mjs", "checkReleaseVersion();");
assertContains("scripts/publish_crates_in_order.mjs", 'const MODE_ORDER = "order";');
assertContains("scripts/publish_crates_in_order.mjs", '["package", "--workspace", "--no-verify", "--locked"]');
assertContains("scripts/publish_crates_in_order.mjs", '"--offline"');
assertContains("scripts/publish_crates_in_order.mjs", "isEarlierWorkspaceDependency");
assertContains("scripts/publish_crates_in_order.mjs", "dry-run reached unpublished ordered workspace dependencies");
assertContains("scripts/publish_crates_in_order.mjs", "retryAfterMs");
assertContains("scripts/publish_crates_in_order.mjs", "too many requests");
assertContains("scripts/publish_crates_in_order.mjs", "rate-limited");
assertContains("scripts/publish_crates_in_order.mjs", "rate limited");
assertContains("scripts/publish_crates_in_order.mjs", "crates.io rate-limited new crate uploads");
assertContains("scripts/publish_crates_in_order.mjs", "crates.io index has not observed a freshly published dependency yet");
assertContains("scripts/publish_crates_in_order.mjs", "already uploaded");
assertContains("scripts/publish_crates_in_order.mjs", "already exists");
assertContains("scripts/publish_crates_in_order.mjs", "verifyPublishedPackageMatches(pkg)");
assertContains("scripts/publish_crates_in_order.mjs", "const publishedChecksum = createHash(\"sha256\")");
assertContains(".github/workflows/protobuf-ci.yml", "name: lint, generated freshness");
assertContains(".github/workflows/protobuf-ci.yml", "runs-on: ubuntu-24.04");
assertNotContains(".github/workflows/protobuf-ci.yml", "runs-on: ubuntu-latest");
assertNotContains(".github/workflows/protobuf-ci.yml", "git fetch origin main:refs/remotes/origin/main");
assertNotContains(".github/workflows/protobuf-ci.yml", "buf breaking --against");
assertContains(".github/workflows/protobuf-ci.yml", "scripts/check_release_readiness.mjs");
assertContains(".github/workflows/protobuf-ci.yml", "scripts/harden-generated-cose-proto.mjs");
assertContains(".github/workflows/fuzz.yml", "- wire");
assertContains(".github/workflows/fuzz.yml", "runs-on: ubuntu-24.04");
assertNotContains(".github/workflows/fuzz.yml", "runs-on: ubuntu-latest");
assertContains(".github/workflows/fuzz.yml", "CARGO_FUZZ_VERSION: 0.13.2");
assertContains(".github/workflows/fuzz.yml", "NIGHTLY_TOOLCHAIN: nightly-2026-07-01");
assertContains(".github/workflows/fuzz.yml", "FUZZ_MAX_TOTAL_TIME_SECONDS: 900");
assertContains(
  ".github/workflows/fuzz.yml",
  "uses: actions/cache@",
);
assertContains(".github/workflows/fuzz.yml", "path: fuzz/corpus/${{ matrix.target }}");
assertContains(".github/workflows/fuzz.yml", "cargo metadata --manifest-path fuzz/Cargo.toml --locked --no-deps");
assertContains(".github/workflows/fuzz.yml", "git diff --exit-code -- fuzz/Cargo.lock");
const cratesPackagePreflightWorkflow = ".github/workflows/crates-package-preflight.yml";
assertContains(cratesPackagePreflightWorkflow, "name: Crates Package Preflight");
assertContains(
  cratesPackagePreflightWorkflow,
  "run-name: Crates package preflight ${{ inputs.version }} @ ${{ github.sha }}",
);
assertContains(cratesPackagePreflightWorkflow, "BUF_VERSION: 1.71.0");
assertContains(cratesPackagePreflightWorkflow, "BUFFA_VERSION: 0.9.0");
assertContains(cratesPackagePreflightWorkflow, "CARGO_DENY_VERSION: 0.20.2");
assertContains(cratesPackagePreflightWorkflow, "CARGO_AUDIT_VERSION: 0.22.2");
assertContains(cratesPackagePreflightWorkflow, "CARGO_NEXTEST_VERSION: 0.9.140");
assertContains(cratesPackagePreflightWorkflow, "CARGO_CHECK_EXTERNAL_TYPES_VERSION: 0.5.0");
assertContains(cratesPackagePreflightWorkflow, "CARGO_FUZZ_VERSION: 0.13.2");
assertContains(cratesPackagePreflightWorkflow, "EXTERNAL_TYPES_NIGHTLY: nightly-2026-03-20");
assertContains(cratesPackagePreflightWorkflow, "FUZZ_NIGHTLY: nightly-2026-07-01");
assertContains(cratesPackagePreflightWorkflow, "WASM_PACK_VERSION: 0.15.0");
assertContains(cratesPackagePreflightWorkflow, "WASM_BINDGEN_CLI_VERSION: 0.2.126");
assertContains(cratesPackagePreflightWorkflow, "version:");
assertContains(
  cratesPackagePreflightWorkflow,
  "group: crates-package-preflight-${{ inputs.version }}-${{ github.sha }}",
);
assertContains(cratesPackagePreflightWorkflow, "verify-source-sha:");
assertContains(cratesPackagePreflightWorkflow, "crates-package:");
assertContains(cratesPackagePreflightWorkflow, "runs-on: ubuntu-24.04");
assertNotContains(cratesPackagePreflightWorkflow, "runs-on: ubuntu-latest");
assertContains(cratesPackagePreflightWorkflow, "ref: ${{ github.sha }}");
assertContains(cratesPackagePreflightWorkflow, "fetch-depth: 0");
assertContains(cratesPackagePreflightWorkflow, "node scripts/verify_release_source.mjs");
assertContains(cratesPackagePreflightWorkflow, "uses: actions/checkout@");
assertContains(cratesPackagePreflightWorkflow, "uses: actions/setup-node@");
assertContains(cratesPackagePreflightWorkflow, "uses: Swatinem/rust-cache@");
assertContains(
  cratesPackagePreflightWorkflow,
  "uses: actions/upload-artifact@",
);
assertContains(cratesPackagePreflightWorkflow, "node scripts/write_release_attestation.mjs");
assertContains(
  cratesPackagePreflightWorkflow,
  "reallyme-cose-crates-preflight-${{ inputs.version }}-${{ github.sha }}",
);
assertContains(cratesPackagePreflightWorkflow, "node-version: '24'");
assertContains(cratesPackagePreflightWorkflow, "BUF_LINUX_X86_64_SHA256:");
assertContains(cratesPackagePreflightWorkflow, "sha256sum --check --strict");
assertContains(".github/workflows/protobuf-ci.yml", "BUF_LINUX_X86_64_SHA256:");
assertContains(".github/workflows/protobuf-ci.yml", "sha256sum --check --strict");
assertContains(cratesPackagePreflightWorkflow, "uses: taiki-e/install-action@");
assertContains(cratesPackagePreflightWorkflow, 'protoc-gen-buffa --version "$BUFFA_VERSION"');
assertContains(cratesPackagePreflightWorkflow, 'protoc-gen-buffa-packaging --version "$BUFFA_VERSION"');
assertContains(cratesPackagePreflightWorkflow, 'cargo install cargo-fuzz --version "$CARGO_FUZZ_VERSION" --locked');
assertContains("scripts/run_pinned_release_readiness.mjs", "f27973caf9d3a12847cac4032c361f5f553c97e9");
assertContains("scripts/run_pinned_release_readiness.mjs", "70cc78721738cf352024938e8fc86e73380e71b2cdf7a9a733687543167cbaae");
assertContains("scripts/verify_release_source.mjs", "main:refs/remotes/origin/main");
assertContains("scripts/verify_release_source.mjs", "manifest-version-mismatch");
assertContains("scripts/verify_release_attestation.mjs", 'value.conclusion !== "success"');
assertContains("scripts/verify_release_attestation.mjs", 'value.event !== "workflow_dispatch"');
assertContains("scripts/verify_release_attestation.mjs", "attestation-input-mismatch");
assertContains("scripts/verify_release_attestation.mjs", 'value.run_attempt !== 1');
assertContains("scripts/verify_release_attestation.mjs", "selectLatestPreflightRun");
assertContains("scripts/verify_release_attestation.mjs", "latest-preflight-run-not-successful");
assertContains("scripts/verify_release_attestation.mjs", "preflight-version-mismatch");
assertContains("scripts/verify_release_attestation.mjs", "preflight-run-id-changed");
assertContains("scripts/write_release_attestation.mjs", "reallyme.cose.crates_preflight.v1");
assertContains(".github/workflows/rust-ci.yml", "runs-on: ubuntu-24.04");
assertNotContains(".github/workflows/rust-ci.yml", "runs-on: ubuntu-latest");
assertContains(".gitignore", "/.release-readiness/");

assertCargoMetadataPolicy({
  packages: [
    {
      name: expectedPackageName,
      version: expectedVersion,
      publish: "public",
      packageFiles: [
        "Cargo.toml",
        "README.md",
        "LICENSE",
        "NOTICE",
        "src/lib.rs",
        "src/wire.rs",
      ],
      dependencies: [
        {
          name: "reallyme-codec",
          requirement: "^0.2.1",
          source: "registry",
          defaultFeatures: false,
        },
        {
          name: "reallyme-crypto",
          requirement: "^0.3.4",
          source: "registry",
          defaultFeatures: false,
        },
      ],
    },
    {
      name: expectedProtoPackageName,
      version: expectedVersion,
      publish: "public",
      packageFiles: [
        "Cargo.toml",
        "README.md",
        "LICENSE",
        "NOTICE",
        "src/lib.rs",
        "src/generated.rs",
        "src/generated/buffa/mod.rs",
        "src/generated/buffa/reallyme.cose.v1.cose.rs",
        "src/generated/buffa/reallyme.cose.v1.cose.__view.rs",
        "proto/reallyme/cose/v1/cose.proto",
      ],
    },
  ],
});

const validationCommands = [
  ["node", ["--test", "scripts/release-readiness/operation-contract-routing.test.mjs"]],
  ["node", ["--test", "scripts/verify_release_attestation.test.mjs"]],
  ["node", ["--test", "scripts/verify_release_source.test.mjs"]],
  ["node", ["--check", "scripts/run_pinned_release_readiness.mjs"]],
  ["node", ["--check", "scripts/verify_release_source.mjs"]],
  ["node", ["--check", "scripts/write_release_attestation.mjs"]],
  ["node", ["--check", "scripts/verify_release_attestation.mjs"]],
  ["node", ["--check", "scripts/harden-generated-cose-proto.mjs"]],
  ["node", ["scripts/harden-generated-cose-proto.mjs", "--check-idempotent"]],
  ["cargo", ["fmt", "--check"]],
  ["cargo", ["check", "--locked", "--workspace", "--all-features"]],
  ["cargo", ["check", "--locked", "--workspace", "--all-features"], { env: { ...process.env, RUSTFLAGS: "-Dwarnings" } }],
  [
    "cargo",
    ["check", "--locked", "--workspace", "--no-default-features"],
    { env: { ...process.env, RUSTFLAGS: "-Dwarnings" } },
  ],
  [
    "cargo",
    ["check", "--locked", "--workspace", "--no-default-features", "--features", "native,wire"],
    { env: { ...process.env, RUSTFLAGS: "-Dwarnings" } },
  ],
  ["cargo", ["clippy", "--locked", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"]],
  [
    "cargo",
    [
      "+nightly-2026-03-20",
      "check-external-types",
      "--manifest-path",
      "crates/cose/Cargo.toml",
      "--all-features",
    ],
  ],
  ["cargo", ["fmt", "--manifest-path", "tools/vector-audit/Cargo.toml", "--check"]],
  ["cargo", ["clippy", "--locked", "--manifest-path", "tools/vector-audit/Cargo.toml", "--all-targets", "--", "-D", "warnings"]],
  ["cargo", ["fmt", "--manifest-path", "tools/vector-goldens/Cargo.toml", "--check"]],
  ["cargo", ["clippy", "--locked", "--manifest-path", "tools/vector-goldens/Cargo.toml", "--all-targets", "--", "-D", "warnings"]],
  ["cargo", ["test", "--locked", "--workspace", "--all-features"]],
  ["cargo", ["bench", "--locked", "--bench", "operation_performance", "--all-features"]],
  ["cargo", ["nextest", "run", "--locked", "--workspace", "--no-default-features", "--features", "native"]],
  ["cargo", ["nextest", "run", "--release", "--locked", "--workspace", "--all-features"]],
  [
    "wasm-pack",
    [
      "test",
      "--node",
      "crates/cose",
      "--no-default-features",
      "--features",
      "wasm",
      "--test",
      "test_wasm_sign1",
    ],
  ],
  ["cargo", ["run", "--locked", "--manifest-path", "tools/vector-audit/Cargo.toml", "--bin", "reallyme-cose-vector-audit", "--", "."]],
  [
    "cargo",
    ["metadata", "--manifest-path", "fuzz/Cargo.toml", "--locked", "--no-deps", "--format-version", "1"],
    { capture: true },
  ],
  ["cargo", ["fmt", "--manifest-path", "fuzz/Cargo.toml", "--check"]],
  ["cargo", ["+nightly-2026-07-01", "fuzz", "build"]],
  ["cargo", ["check", "--locked", "--workspace", "--no-default-features", "--features", "native"]],
  [
    "cargo",
    [
      "check",
      "--locked",
      "--workspace",
      "--target",
      "wasm32-unknown-unknown",
      "--no-default-features",
      "--features",
      "wasm",
    ],
  ],
  [
    "cargo",
    [
      "check",
      "--locked",
      "--workspace",
      "--target",
      "wasm32-unknown-unknown",
      "--no-default-features",
      "--features",
      "wasm,wire",
    ],
  ],
  ["cargo", ["deny", "check"]],
  ["cargo", ["audit", "--deny", "warnings"]],
];

if (!policyOnlyMode && !generatedFreshnessMode) {
  runCommands(validationCommands);
}

const readinessMode = generatedFreshnessMode
  ? "generated freshness "
  : policyOnlyMode
    ? "policy "
    : releasePackagesMode
      ? "release package "
    : "";
console.log(
  `${expectedPackageName} ${expectedVersion} release readiness ${readinessMode}checks passed`,
);
