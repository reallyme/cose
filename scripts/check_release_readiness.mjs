#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

import { isDeepStrictEqual } from "node:util";
import { assertCompleteTypeContract } from "./check_type_contract.mjs";
import { assertGuardedBuffaContract } from "./check_buffa_contract.mjs";
import { assertCompleteOperationContract } from "./check_operation_contract.mjs";

import { assertOperationContractRouting } from "./release-readiness/operation-contract-routing.mjs";

const releaseReadinessCoreUrl = process.env.RELEASE_READINESS_CORE_URL;
if (process.env.RELEASE_READINESS_ENFORCED_VERSION !== "0.9.5" || !releaseReadinessCoreUrl) {
  console.error("Run the COSE checker through the pinned Release Readiness 0.9.5 runner.");
  process.exit(1);
}
const { createReleaseReadinessContext } = await import(releaseReadinessCoreUrl);

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
  root,
  assertWorkflowRunStep,
  assertWorkflowUsesStepPinnedTo,
  assertPathsAbsent,
  extractWorkflowSteps,
  readWorkflowStepInputs,
  assertWorkflowActionsPinned,
  assertCargoFuzzWorkflowPolicy,
  assertFuzzLockfileWorkflow,
  assertReallyMeReleasePackagePolicy,
  assertRustReleasePolicy,
  assertTextPolicy,
  assertCargoMetadataPolicy,
  assertSpdxHeaders,
  assertRustSourcePolicy,
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
  minimumInstallations: 1,
  requiredInstallSteps: [
    { job: "build", name: "Install cargo-fuzz" },
  ],
});
assertCargoFuzzWorkflowPolicy({
  workflow: ".github/workflows/fuzz-scheduled.yml",
  version: "0.13.2",
  minimumInstallations: 1,
  requiredInstallSteps: [{ job: "scheduled", name: "Install cargo-fuzz" }],
});
assertReallyMeReleasePackagePolicy({ version: "0.9.5" });
assertPathsAbsent([
  "scripts/release-readiness/core.mjs",
  "scripts/sanitize_enum_diagnostics.mjs",
]);
const rustCi = { workflow: ".github/workflows/rust-ci.yml", job: "rust" };
assertRustReleasePolicy({
  release: { ...rustCi, step: "Test locked release toolchain" },
  msrv: [
    { ...rustCi, package: "reallyme-cose", step: "Test COSE at MSRV" },
    { ...rustCi, package: "reallyme-cose-proto", step: "Test COSE protobuf at MSRV" },
  ],
  dependencyReview: { ...rustCi, step: "Review locked Rust dependencies" },
});
assertRustSourcePolicy({
  roots: ["."],
  generatedPrefixes: ["crates/proto/src/generated"],
  moduleHardLines: 150,
});
// Generated sources are covered by their crate's bundled license text.
assertSpdxHeaders({
  extensions: [".rs", ".mjs", ".js", ".sh", ".py"],
  names: [],
  copyright: "SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited",
  license: "SPDX-License-Identifier: MIT OR Apache-2.0",
  excludedPrefixes: ["crates/proto/src/generated"],
});
assertContains("Cargo.toml", 'license = "MIT OR Apache-2.0"');
for (const manifest of ["fuzz/Cargo.toml", "tools/vector-audit/Cargo.toml", "tools/vector-goldens/Cargo.toml"]) {
  assertContains(manifest, 'license = "MIT OR Apache-2.0"');
}
if (readText("crates/cose/README.md") !== readText("README.md")) {
  fail("crates/cose/README.md must match the repository README.md");
}
for (const packageDirectory of ["crates/cose", "crates/proto"]) {
  assertContains(`${packageDirectory}/Cargo.toml`, "license.workspace = true");
  for (const file of ["LICENSE", "NOTICE"]) {
    if (readText(`${packageDirectory}/${file}`) !== readText(file)) {
      fail(`${packageDirectory}/${file} must match the repository ${file}`);
    }
  }
}
assertContains(".github/dependabot.yml", "groups:");
assertContains(".github/dependabot.yml", "github-actions:");

const expectedPackageName = "reallyme-cose";
const expectedProtoPackageName = "reallyme-cose-proto";
const expectedVersion = "0.3.0";
const expectedDevelopmentRustToolchain = "1.100.0";
const expectedBufLinuxX86_64Sha256 =
  "8f2986298ad08f0cc1bf999b9797b7c383adf32d7edf0f73d6f1e1a701baeac1";
const generatedFreshnessMode = process.argv.includes("--generated-freshness");
const policyOnlyMode = process.argv.includes("--policy-only") ||
  (process.argv.length === 2 && process.env.COSE_RELEASE_READINESS_POLICY_ONLY === "1");
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
  spdxCopyrightText: "2026 ReallyMe Technologies Limited",
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
const platformScopePath = "docs/platform-scope-0.3.0.json";
const platformScope = readJson(platformScopePath);
if (!isDeepStrictEqual(platformScope, expectedPlatformScope)) {
  fail(`${platformScopePath} must exactly match the approved 0.3.0 platform scope`);
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
    fail(`${trackedFile} is outside the approved Rust/protobuf-only 0.3.0 scope`);
  }
}

for (const obsoleteRoot of ["benches/", "conformance/", "src/", "tests/"]) {
  for (const trackedFile of loadTrackedFiles()) {
    if (trackedFile.startsWith(obsoleteRoot)) {
      fail(`${trackedFile} is outside the canonical workspace layout`);
    }
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
assertContains("README.md", "## 0.3.0 Platform Scope");
assertContains(
  "README.md",
  "The `0.3.0` distribution does not include Swift, Android/Kotlin, Kotlin/JVM",
);

assertNodeWorkflowJobsPinNode({ nodeVersion: "26" });

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
assertContains("crates/cose/Cargo.toml", "buffa.workspace = true");
assertContains("crates/cose/Cargo.toml", 'reallyme-cose-proto = { workspace = true, features = ["generated"] }');
assertContains("crates/cose/Cargo.toml", '"dep:serde"');
assertContains("crates/cose/Cargo.toml", '"dep:serde_json"');
assertContains(
  "Cargo.toml",
  'reallyme-codec = { version = "0.4.3", default-features = false, features = ["base64url", "cbor", "multikey"] }',
);
assertNotContains("Cargo.toml", 'path = "../codec');
assertContains("crates/proto/Cargo.toml", '"buffa/json"');
assertContains("crates/cose/src/lib.rs", 'reallyme-cose `wire` requires a runtime lane');
assertContains("Cargo.toml", 'buffa = { package = "reallyme-buffa", version = "=0.1.2", features = ["json", "zeroize"] }');
assertContains("Cargo.toml", 'rust-version = "1.100"');
assertContains("rust-toolchain.toml", `channel = "${expectedDevelopmentRustToolchain}"`);
assertContains(
  "Cargo.toml",
  `reallyme-cose-proto = { version = "${expectedVersion}", path = "crates/proto", default-features = false }`,
);
assertContains("Cargo.toml", 'serde = { version = "1.0.229", features = ["derive"] }');
assertContains("Cargo.toml", 'serde_json = "1.0.154"');
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
assertContains(".github/workflows/fuzz-scheduled.yml", "cose_encrypt");
assertContains("crates/cose/src/generated_contract/cose_ml_kem_algorithm.rs", "pub enum CoseMlKemAlgorithm");
assertContains("crates/cose/src/generated_contract/cose_ml_kem_encrypt_request.rs", "#[non_exhaustive]\npub struct CoseMlKemEncryptRequest");
assertContains("crates/cose/src/generated_contract/cose_ml_kem_encrypt_request.rs", "pub(crate) kem_algorithm: super::CoseMlKemAlgorithm");
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
  "The exact-algorithm native verifier variants pass",
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
assertContains("crates/cose/src/key/facade.rs", "Result<Zeroizing<Vec<u8>>, CoseError>");
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
  "super::key::parse::result(core::mem::take(&mut **request))",
);
for (const semanticRoute of [
  "construct_cose_key_from_public(CoseKeyFromPublicBytesInput::new(",
  "construct_cose_key_from_private(CoseKeyFromPrivateBytesInput::new(",
  "extract_cose_key_public(CoseKeyRefInput::new(",
  "extract_cose_key_private(CoseKeyRefInput::new(",
]) {
  assertContains("crates/cose/src/key/facade.rs", semanticRoute);
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
  "super::key::convert::from_public_bytes_result(core::mem::take(&mut **request))",
  "super::key::convert::from_private_bytes_result(core::mem::take(&mut **request))",
  "super::key::convert::to_public_bytes_result(core::mem::take(&mut **request))",
  "super::key::convert::to_private_bytes_result(core::mem::take(&mut **request))",
  "super::key::convert::derive_public_kid_result(core::mem::take(&mut **request))",
  "super::key::convert::to_multikey_result(core::mem::take(&mut **request))",
  "super::key::convert::multikey_to_key_result(core::mem::take(&mut **request))",
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
  "super::sign1::create::attached_result(core::mem::take(&mut **request))",
  "super::sign1::create::detached_result(core::mem::take(&mut **request))",
  "super::sign1::verify::attached_result(core::mem::take(&mut **request))",
  "super::sign1::verify::detached_result(core::mem::take(&mut **request))",
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
  "super::encrypt::create::direct_result(core::mem::take(&mut **request))",
  "super::encrypt::create::key_wrap_result(core::mem::take(&mut **request))",
  "super::encrypt::decrypt::result(core::mem::take(&mut **request))",
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
assertCompleteOperationContract({ readText, loadTrackedFiles, fail });
assertCompleteTypeContract({readText,loadTrackedFiles,fail});
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
assertContains("crates/proto/Cargo.toml", `name = "${expectedProtoPackageName}"`);
assertContains("crates/proto/Cargo.toml", `version = "${expectedVersion}"`);
assertContains("crates/proto/Cargo.toml", "publish = true");
assertContains("crates/proto/src/generated.rs", "COSE_PROTO_PACKAGE");
assertGuardedBuffaContract({root,readText,fail,assertWorkflowRunStep,installBufRun:verifiedBufInstallCommand},generatedFreshnessMode);
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
assertContains(
  "crates/proto/proto/reallyme/cose/v1/cose.proto",
  "COSE_SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 = 200 [deprecated = true];",
);
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "COSE_SIGNATURE_ALGORITHM_ES256 = 201;");
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "COSE_SIGNATURE_ALGORITHM_ESP256 = 202;");
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
assertContains(
  "crates/proto/proto/reallyme/cose/v1/cose.proto",
  "CoseSignatureAlgorithm exact_signature_algorithm = 4;",
);
assertContains("crates/proto/proto/reallyme/cose/v1/cose.proto", "message CoseKeyBytesResult");
const protoSource = readText("crates/proto/proto/reallyme/cose/v1/cose.proto");
for (const marker of [
  "SENSITIVE: raw private key bytes",
  "SENSITIVE: payload bytes",
  "SENSITIVE: encoded COSE_Key bytes",
  "SENSITIVE: operation-specific bytes",
]) {
  if (!protoSource.includes(marker)) {
    fail("protobuf schema must retain its sensitive field annotations");
  }
}
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
assertContains("crates/cose/src/sign1/provider.rs", "pub type CoseSignerError = CoseError;");
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
assertContains("crates/cose/src/policy/validate.rs", "contract: ContractPolicy");
assertContains("crates/cose/src/policy/validate.rs", "pub fn with_require_kid");
assertNotContains("crates/cose/src/policy/validate.rs", "pub require_kid: bool");
assertNotContains("crates/cose/src/policy/validate.rs", "pub allowed_algs: Vec<Algorithm>");
assertNotContains("crates/cose/src/policy/validate.rs", "pub max_cose_sign1_bytes: usize");
assertContains("crates/cose/src/sign1/sign.rs", "#[must_use]\n#[derive(Clone, Debug, Eq, PartialEq)]\npub struct CoseSign1EncodeOptions");
assertContains("crates/cose/src/sign1/sign.rs", "contract: crate::api::contract::CoseSign1Options");
assertContains("crates/cose/src/sign1/sign.rs", "pub fn tagged()");
assertNotContains("crates/cose/src/sign1/sign.rs", "pub tag: bool");
assertNotContains("crates/cose/src/sign1/sign.rs", "pub max_cose_sign1_bytes: usize");
assertContains("crates/cose/src/generated_contract/verified_cose_sign1.rs", "#[must_use]\n#[non_exhaustive]\npub struct VerifiedCoseSign1");
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
for (const command of [
  "tools/vector-goldens/Cargo.toml",
  "--features native,wire",
  "--features wasm,wire --target wasm32-unknown-unknown",
  "cargo nextest run --release --locked --workspace --all-features",
  "cargo bench --locked --bench operation_performance --all-features",
  "wasm-pack test --node crates/cose",
  "WASM_BINDGEN_CLI_VERSION: 0.2.130",
  "CARGO_CHECK_EXTERNAL_TYPES_VERSION: 0.5.0",
  "EXTERNAL_TYPES_NIGHTLY: nightly-2026-09-15",
  "bash scripts/install_external_type_checker.sh .local-tools",
  "check-external-types --manifest-path crates/cose/Cargo.toml --all-features",
  "scripts/audit_committed_lockfiles.sh",
]) {
  assertContains(rustCi.workflow, command);
}
for (const workflow of [
  ".github/workflows/release-readiness.yml",
  ".github/workflows/protobuf-ci.yml",
  ".github/workflows/crates-package-preflight.yml",
  ".github/workflows/crates-release.yml",
]) {
  const checkout = "Checkout release-readiness runner";
  assertWorkflowUsesStepPinnedTo(workflow, checkout, "actions/checkout");
  const step = extractWorkflowSteps(workflow).find(({ name }) => name === checkout);
  const inputs = readWorkflowStepInputs(workflow, step, readText(workflow).split(/\r?\n/u));
  if (step.condition !== null ||
      inputs.get("repository") !== "reallyme/release-readiness" ||
      inputs.get("ref") !== "55115f21d5bf9a3fbc1bb8d10484aecba6e7bd8f" ||
      inputs.get("path") !== ".release-readiness" ||
      inputs.get("persist-credentials") !== "false") {
    fail(`${workflow} must check out the reviewed Release Readiness package without credentials`);
  }
}
const preflightWorkflow = ".github/workflows/crates-package-preflight.yml";
const publishWorkflow = ".github/workflows/crates-release.yml";
for (const workflow of [preflightWorkflow, publishWorkflow]) {
  const step = assertWorkflowRunStep(workflow, "Enforce package release policy",
    "node .release-readiness/scripts/run-consumer-check.mjs --release-packages", "verify");
  if (step.condition !== null || (step.continueOnError !== null && step.continueOnError !== "false")) {
    fail(`${workflow} must enforce the package release policy before verifying the candidate`);
  }
}
assertWorkflowRunStep(preflightWorkflow, "Inspect and stage verified crate archives",
  "node scripts/publish_crates_in_order.mjs inspect", "crates-package");
assertWorkflowRunStep(publishWorkflow, "Publish crates in reviewed dependency order",
  "node scripts/publish_crates_in_order.mjs publish", "publish");
assertNotContains(preflightWorkflow, "CARGO_REGISTRY_TOKEN");
assertContains(publishWorkflow, "CARGO_REGISTRY_TOKEN");
assertNotContains(publishWorkflow, "git push");
assertContains(publishWorkflow, 'tag="reallyme-cose-v${RELEASE_VERSION}"');
assertContains(publishWorkflow, "gh release create");
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
assertContains(
  ".github/workflows/protobuf-ci.yml",
  `toolchain: ${expectedDevelopmentRustToolchain}`,
);
assertNotContains(".github/workflows/protobuf-ci.yml", "git fetch origin main:refs/remotes/origin/main");
assertNotContains(".github/workflows/protobuf-ci.yml", "buf breaking --against");
assertFuzzLockfileWorkflow(".github/workflows/fuzz.yml", "build");
assertFuzzLockfileWorkflow(".github/workflows/fuzz-scheduled.yml", "scheduled");
assertContains(".github/workflows/fuzz.yml", "git diff --exit-code -- fuzz/Cargo.lock");
assertContains(".github/workflows/fuzz-scheduled.yml", "- wire");
assertContains(".github/workflows/fuzz-scheduled.yml", "FUZZ_MAX_TOTAL_TIME_SECONDS: 900");
assertContains(".github/workflows/fuzz-scheduled.yml", "path: fuzz/corpus/${{ matrix.target }}");
assertContains("deny.toml", 'yanked = "deny"');
assertContains("scripts/run_pinned_release_readiness.mjs", "55115f21d5bf9a3fbc1bb8d10484aecba6e7bd8f");
assertContains(".gitignore", "/.release-readiness/");
assertContains(".gitignore", "/.local-tools/");
assertContains(
  "scripts/install_external_type_checker.sh",
  'upstream_commit="61d284da26e8bbaca386a5b9f34bee30e82aaa0e"',
);
assertContains("tools/external-type-checker-rustdoc61.patch", '+rustdoc-types = "0.61"');

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
          requirement: "^0.4.3",
          source: "registry",
          defaultFeatures: false,
        },
        {
          name: "reallyme-crypto",
          requirement: "^0.4.2",
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
  ["node", ["--test", "scripts/publish_crates_in_order.test.mjs"]],
  ["node", ["--test", "scripts/generate_cose_contract.test.mjs"]],
  ["node", ["--test", "scripts/release-readiness/operation-contract-routing.test.mjs"]],
  ["node", ["--test", "scripts/check_operation_contract.test.mjs", "scripts/check_type_contract.test.mjs"]],
  ["node", ["--check", "scripts/run_pinned_release_readiness.mjs"]],
  ["node", ["--check", "scripts/generate_cose_contract.mjs"]],
  ["node", ["scripts/generate_cose_contract.mjs", "--check"]],
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
    ".local-tools/bin/cargo-check-external-types",
    ["check-external-types", "--manifest-path", "crates/cose/Cargo.toml", "--all-features"],
    { env: { ...process.env, RUSTUP_TOOLCHAIN: "nightly-2026-09-15" } },
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
  ["wasm-pack", ["test", "--node", "crates/cose", "--no-default-features", "--features", "wasm", "--lib"]],
  [
    "cargo",
    ["metadata", "--manifest-path", "fuzz/Cargo.toml", "--locked", "--no-deps", "--format-version", "1"],
    { capture: true },
  ],
  ["cargo", ["fmt", "--manifest-path", "fuzz/Cargo.toml", "--check"]],
  ["cargo", ["+nightly-2026-09-15", "fuzz", "build"]],
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

if (selectedModes.length === 0) {
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
