#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const generated = resolve(
  root,
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.rs",
);
const oneof = resolve(
  root,
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.__oneof.rs",
);
const generatedView = resolve(
  root,
  "crates/proto/src/generated/buffa/reallyme.cose.v1.cose.__view.rs",
);
const protoSource = readFileSync(
  resolve(root, "crates/proto/proto/reallyme/cose/v1/cose.proto"),
  "utf8",
);
const sensitiveScalarMessageNames = [
  ...protoSource.matchAll(/message\s+(\w+)\s*\{([\s\S]*?)\n\}/gu),
]
  .filter((match) => /\b(?:bytes|string)\s+\w+\s*=/u.test(match[2]))
  .map((match) => match[1]);
const oneofCount = [...protoSource.matchAll(/\boneof\s+\w+\s*\{/gu)].length;
const supportedArguments = new Set(["--check-idempotent"]);
const suppliedArguments = new Set();

function fail(message) {
  console.error(`generated COSE proto hardening failed: ${message}`);
  process.exit(1);
}

for (const argument of process.argv.slice(2)) {
  if (!supportedArguments.has(argument)) {
    fail(`unsupported argument ${argument}`);
  }
  if (suppliedArguments.has(argument)) {
    fail(`argument ${argument} was specified more than once`);
  }
  suppliedArguments.add(argument);
}
const checkIdempotent = suppliedArguments.has("--check-idempotent");

function replaceOnce(text, before, after, path) {
  const next = text.replace(before, after);
  if (next === text) {
    fail(`${path} did not contain expected generated fragment: ${before}`);
  }
  return next;
}

function hardenSecretMessage(text, name, privateFieldLine) {
  const marker = `pub struct ${name} {`;
  const markerIndex = text.indexOf(marker);
  if (markerIndex < 0) {
    fail(`${generated} is missing ${name}`);
  }

  const serdeDerive = "#[derive(::serde::Serialize, ::serde::Deserialize)]";
  const hardenedSerdeDerive = "#[derive(::serde::Serialize)]";
  const cloneDerive = "#[derive(Clone, PartialEq, Default)]";
  const structHeader = text.slice(
    Math.max(0, markerIndex - 512),
    markerIndex + marker.length,
  );
  if (!structHeader.includes(cloneDerive)) {
    fail(`${name} is missing the Buffa-required Clone derive`);
  }

  const dropImpl = `impl ::core::ops::Drop for ${name} {
    fn drop(&mut self) {
        ::zeroize::Zeroize::zeroize(&mut self.private_key);
    }
}
`;
  const hardenedDropPattern = new RegExp(
    `impl ::core::ops::Drop for ${name} \\{[\\s\\S]*?::zeroize::Zeroize::zeroize\\(&mut self\\.private_key\\);[\\s\\S]*?\\n\\}\\n`,
    "u",
  );
  const deserializeImpl = secretDeserializeImpl(name);
  const deserializeMarker = `impl<'de> ::serde::Deserialize<'de> for ${name} {`;
  const deserializeIndex = text.indexOf(deserializeMarker, markerIndex);
  const inherentIndex = text.indexOf(`impl ${name} {`, markerIndex);
  const hardenedDeserialize =
    deserializeIndex >= 0 &&
    inherentIndex > deserializeIndex &&
    text
      .slice(deserializeIndex, inherentIndex)
      .includes(".map(::zeroize::Zeroizing::new)") &&
    text
      .slice(deserializeIndex, inherentIndex)
      .includes("private_key: ::core::mem::take(&mut *wire.private_key)");
  if (
    structHeader.includes(hardenedSerdeDerive) &&
    hardenedDropPattern.test(text) &&
    hardenedDeserialize &&
    !text.includes(privateFieldLine)
  ) {
    return text;
  }

  const serdePrefix = text.slice(0, markerIndex);
  const serdeDeriveIndex = serdePrefix.lastIndexOf(serdeDerive);
  if (serdeDeriveIndex < 0) {
    fail(`${name} is missing the expected serde derive`);
  }
  text =
    text.slice(0, serdeDeriveIndex) +
    "#[derive(::serde::Serialize)]" +
    text.slice(serdeDeriveIndex + serdeDerive.length);

  text = replaceOnce(
    text,
    privateFieldLine,
    '            .field("private_key", &"<redacted>")',
    generated,
  );

  text = replaceOnce(
    text,
    "        self.private_key.clear();",
    "        ::zeroize::Zeroize::zeroize(&mut self.private_key);",
    generated,
  );

  const implMarker = `impl ${name} {`;
  const implIndex = text.indexOf(implMarker, markerIndex);
  if (implIndex < 0) {
    fail(`${generated} is missing inherent impl for ${name}`);
  }

  if (hardenedDropPattern.test(text) || deserializeIndex >= 0) {
    fail(`${name} is only partially hardened`);
  }

  return text.slice(0, implIndex) + dropImpl + deserializeImpl + text.slice(implIndex);
}

function redactDebugBytes(text, fieldName) {
  return text.replaceAll(
    `.field("${fieldName}", &self.${fieldName})`,
    `.field("${fieldName}", &"<redacted>")`,
  );
}

function hardenBorrowedViewDebug(text, name) {
  const viewName = `${name}View`;
  const deriveAndStruct = `#[derive(Clone, Debug, Default)]
pub struct ${viewName}<'a> {`;
  const replacement = `#[derive(Clone, Default)]
pub struct ${viewName}<'a> {`;
  const redactedViewDebug = `impl ::core::fmt::Debug for ${viewName}<'_> {
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("${viewName}(<redacted>)")
    }
}
`;
  const ownedViewName = `${name}OwnedView`;
  const ownedReplacement = `#[derive(Clone)]
pub struct ${ownedViewName}(`;
  const redactedOwnedDebug = `impl ::core::fmt::Debug for ${ownedViewName} {
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("${ownedViewName}(<redacted>)")
    }
}
`;
  if (
    text.includes(replacement) &&
    text.includes(redactedViewDebug) &&
    text.includes(ownedReplacement) &&
    text.includes(redactedOwnedDebug)
  ) {
    return text;
  }
  text = replaceOnce(text, deriveAndStruct, replacement, generatedView);

  const messageViewPattern = new RegExp(
    `impl<'a> ::buffa::MessageView<'a>\\s+for ${viewName}<'a> \\{`,
    "u",
  );
  if (!messageViewPattern.test(text)) {
    fail(`${generatedView} is missing MessageView for ${viewName}`);
  }
  text = text.replace(
    messageViewPattern,
    (messageViewImpl) => `${redactedViewDebug}${messageViewImpl}`,
  );

  const ownedDeriveAndStruct = `#[derive(Clone, Debug)]
pub struct ${ownedViewName}(`;
  text = replaceOnce(text, ownedDeriveAndStruct, ownedReplacement, generatedView);

  const ownedImpl = `impl ${ownedViewName} {`;
  return replaceOnce(
    text,
    ownedImpl,
    `${redactedOwnedDebug}${ownedImpl}`,
    generatedView,
  );
}

function hardenByteFieldsOnDrop(text, name, fieldNames) {
  const body = [
    ...fieldNames.map(
      (fieldName) => `        ::zeroize::Zeroize::zeroize(&mut self.${fieldName});`,
    ),
    "        __reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);",
  ].join("\n");
  const dropImpl = `impl ::core::ops::Drop for ${name} {
    fn drop(&mut self) {
${body}
    }
}
`;

  const existingDropPattern = new RegExp(
    `impl ::core::ops::Drop for ${name} \\{\\n    fn drop\\(&mut self\\) \\{\\n[\\s\\S]*?    \\}\\n\\}\\n`,
  );
  if (existingDropPattern.test(text)) {
    return text.replace(existingDropPattern, dropImpl);
  }

  const implMarker = `impl ${name} {`;
  const implIndex = text.indexOf(implMarker);
  if (implIndex < 0) {
    fail(`${generated} is missing inherent impl for ${name}`);
  }
  return text.slice(0, implIndex) + dropImpl + text.slice(implIndex);
}

function secretDeserializeImpl(name) {
  if (name === "CoseSign1CreateRequest" || name === "CoseSign1CreateDetachedRequest") {
    return `impl<'de> ::serde::Deserialize<'de> for ${name} {
    fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        fn deserialize_secret_bytes<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::bytes::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }

        #[derive(Default, ::serde::Deserialize)]
        #[serde(default)]
        struct Wire {
            #[serde(rename = "algorithm", with = "::buffa::json_helpers::proto_enum")]
            algorithm: ::buffa::EnumValue<CoseSignatureAlgorithm>,
            #[serde(rename = "payload", deserialize_with = "deserialize_secret_bytes")]
            payload: ::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>,
            #[serde(
                rename = "privateKey",
                alias = "private_key",
                deserialize_with = "deserialize_secret_bytes"
            )]
            private_key: ::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>,
            #[serde(rename = "kid", deserialize_with = "deserialize_secret_bytes")]
            kid: ::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>,
            #[serde(
                rename = "hasKid",
                alias = "has_kid",
                with = "::buffa::json_helpers::proto_bool"
            )]
            has_kid: bool,
            #[serde(rename = "options")]
            options: ::buffa::MessageField<CoseSign1Options, ::buffa::Inline<CoseSign1Options>>,
            #[serde(
                rename = "externalAad",
                alias = "external_aad",
                deserialize_with = "deserialize_secret_bytes"
            )]
            external_aad: ::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>,
        }

        let mut wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            algorithm: wire.algorithm,
            payload: ::core::mem::take(&mut *wire.payload),
            private_key: ::core::mem::take(&mut *wire.private_key),
            kid: ::core::mem::take(&mut *wire.kid),
            has_kid: wire.has_kid,
            options: ::core::mem::take(&mut wire.options),
            external_aad: ::core::mem::take(&mut *wire.external_aad),
            __buffa_unknown_fields: Default::default(),
        })
    }
}
`;
  }

  if (name === "CoseKeyFromPrivateBytesRequest") {
    return `impl<'de> ::serde::Deserialize<'de> for ${name} {
    fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        fn deserialize_secret_bytes<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::bytes::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }

        #[derive(Default, ::serde::Deserialize)]
        #[serde(default)]
        struct Wire {
            #[serde(rename = "algorithm")]
            algorithm: ::buffa::MessageField<CoseAlgorithmIdentifier, ::buffa::Inline<CoseAlgorithmIdentifier>>,
            #[serde(
                rename = "privateKey",
                alias = "private_key",
                deserialize_with = "deserialize_secret_bytes"
            )]
            private_key: ::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>,
            #[serde(
                rename = "publicKey",
                alias = "public_key",
                deserialize_with = "deserialize_secret_bytes"
            )]
            public_key: ::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>,
            #[serde(
                rename = "hasPublicKey",
                alias = "has_public_key",
                with = "::buffa::json_helpers::proto_bool"
            )]
            has_public_key: bool,
        }

        let mut wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            algorithm: wire.algorithm,
            private_key: ::core::mem::take(&mut *wire.private_key),
            public_key: ::core::mem::take(&mut *wire.public_key),
            has_public_key: wire.has_public_key,
            __buffa_unknown_fields: Default::default(),
        })
    }
}
`;
  }

  fail(`no secret Deserialize hardening template for ${name}`);
}

function genericSensitiveDeserializeImpl(name, fields) {
  const hasSensitiveBytes = fields.some((field) => field.kind === "bytes");
  const hasSensitiveString = fields.some((field) => field.kind === "string");
  const wireFields = fields
    .map((field) => {
      const alias = field.jsonName === field.name ? "" : `, alias = "${field.name}"`;
      if (field.kind === "bytes") {
        return `            #[serde(rename = "${field.jsonName}"${alias}, deserialize_with = "deserialize_secret_bytes")]
            ${field.name}: ::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>,`;
      }
      if (field.kind === "string") {
        return `            #[serde(rename = "${field.jsonName}"${alias}, deserialize_with = "deserialize_secret_string")]
            ${field.name}: ::zeroize::Zeroizing<::buffa::alloc::string::String>,`;
      }
      if (field.kind === "enum") {
        return `            #[serde(rename = "${field.jsonName}"${alias}, with = "::buffa::json_helpers::proto_enum")]
            ${field.name}: ::buffa::EnumValue<${field.enumName}>,`;
      }
      if (field.kind === "message") {
        return `            #[serde(rename = "${field.jsonName}"${alias})]
            ${field.name}: ::buffa::MessageField<${field.messageName}, ::buffa::Inline<${field.messageName}>>,`;
      }
      if (field.kind === "repeated_enum") {
        return `            #[serde(rename = "${field.jsonName}"${alias}, with = "::buffa::json_helpers::repeated_enum")]
            ${field.name}: ::buffa::alloc::vec::Vec<::buffa::EnumValue<${field.enumName}>>,`;
      }
      if (field.kind === "u64") {
        return `            #[serde(rename = "${field.jsonName}"${alias}, with = "::buffa::json_helpers::uint64")]
            ${field.name}: u64,`;
      }
      if (field.kind === "bool") {
        return `            #[serde(rename = "${field.jsonName}"${alias}, with = "::buffa::json_helpers::proto_bool")]
            ${field.name}: bool,`;
      }
      fail(`unsupported generated sensitive field kind ${field.kind} for ${name}`);
    })
    .join("\n");
  const assignments = fields
    .map((field) => {
      if (field.kind === "bytes" || field.kind === "string") {
        return `            ${field.name}: ::core::mem::take(&mut *wire.${field.name}),`;
      }
      if (field.kind === "repeated_enum") {
        return `            ${field.name}: ::core::mem::take(&mut wire.${field.name}),`;
      }
      if (field.kind === "message") {
        return `            ${field.name}: ::core::mem::take(&mut wire.${field.name}),`;
      }
      return `            ${field.name}: wire.${field.name},`;
    })
    .join("\n");

  const bytesDeserializer = hasSensitiveBytes
    ? `        fn deserialize_secret_bytes<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::bytes::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }

`
    : "";
  const stringDeserializer = hasSensitiveString
    ? `        fn deserialize_secret_string<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::string::String>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            <::buffa::alloc::string::String as ::serde::Deserialize>::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }

`
    : "";

  return `impl<'de> ::serde::Deserialize<'de> for ${name} {
    fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
${bytesDeserializer}${stringDeserializer}
        #[derive(Default, ::serde::Deserialize)]
        #[serde(default)]
        struct Wire {
${wireFields}
        }

        let mut wire = Wire::deserialize(deserializer)?;
        Ok(Self {
${assignments}
            __buffa_unknown_fields: Default::default(),
        })
    }
}
`;
}

function hardenSensitiveDeserialize(text, name, fields) {
  const marker = `pub struct ${name} {`;
  const markerIndex = text.indexOf(marker);
  if (markerIndex < 0) {
    fail(`${generated} is missing ${name}`);
  }
  const serdeDerive = "#[derive(::serde::Serialize, ::serde::Deserialize)]";
  const hardenedSerdeDerive = "#[derive(::serde::Serialize)]";
  const deserializeImpl = genericSensitiveDeserializeImpl(name, fields);
  const structHeader = text.slice(Math.max(0, markerIndex - 512), markerIndex);
  const deserializeMarker = `impl<'de> ::serde::Deserialize<'de> for ${name} {`;
  const deserializeIndex = text.indexOf(deserializeMarker, markerIndex);
  const inherentIndex = text.indexOf(`impl ${name} {`, markerIndex);
  const hardenedDeserialize =
    deserializeIndex >= 0 &&
    inherentIndex > deserializeIndex &&
    text
      .slice(deserializeIndex, inherentIndex)
      .includes(".map(::zeroize::Zeroizing::new)") &&
    text
      .slice(deserializeIndex, inherentIndex)
      .includes("__buffa_unknown_fields: Default::default()");
  if (structHeader.includes(hardenedSerdeDerive) && hardenedDeserialize) {
    return text;
  }
  const serdePrefix = text.slice(0, markerIndex);
  const serdeDeriveIndex = serdePrefix.lastIndexOf(serdeDerive);
  if (serdeDeriveIndex < 0) {
    fail(`${name} is missing the expected serde derive`);
  }
  text =
    text.slice(0, serdeDeriveIndex) +
    "#[derive(::serde::Serialize)]" +
    text.slice(serdeDeriveIndex + serdeDerive.length);

  const implMarker = `impl ${name} {`;
  const implIndex = text.indexOf(implMarker, markerIndex);
  if (implIndex < 0) {
    fail(`${generated} is missing inherent impl for ${name}`);
  }
  if (deserializeIndex >= 0 || text.includes(deserializeImpl)) {
    fail(`${name} is only partially JSON-hardened`);
  }
  return text.slice(0, implIndex) + deserializeImpl + text.slice(implIndex);
}

let generatedText = readFileSync(generated, "utf8");
const generatedHeader = `// @generated by buffa-codegen. DO NOT EDIT.
// source: reallyme/cose/v1/cose.proto
`;
const unknownFieldZeroizeHelpers = `
fn __reallyme_zeroize_unknown_fields(fields: &mut ::buffa::UnknownFields) {
    for mut field in ::core::mem::take(fields) {
        __reallyme_zeroize_unknown_field_data(&mut field.data);
    }
}

fn __reallyme_zeroize_unknown_field_data(data: &mut ::buffa::UnknownFieldData) {
    match data {
        ::buffa::UnknownFieldData::LengthDelimited(bytes) => {
            ::zeroize::Zeroize::zeroize(bytes);
        }
        ::buffa::UnknownFieldData::Group(fields) => {
            __reallyme_zeroize_unknown_fields(fields);
        }
        ::buffa::UnknownFieldData::Varint(_)
        | ::buffa::UnknownFieldData::Fixed64(_)
        | ::buffa::UnknownFieldData::Fixed32(_) => {}
    }
}
`;
if (!generatedText.includes("__reallyme_zeroize_unknown_fields")) {
  generatedText = replaceOnce(
    generatedText,
    generatedHeader,
    `${generatedHeader}${unknownFieldZeroizeHelpers}`,
    generated,
  );
}
generatedText = hardenSecretMessage(
  generatedText,
  "CoseSign1CreateRequest",
  '            .field("private_key", &self.private_key)',
);
for (const [name, fields] of [
  ["CoseSign1CreateResult", [{ name: "cose_sign1", jsonName: "coseSign1", kind: "bytes" }]],
  [
    "CoseSign1VerifyRequest",
    [
      { name: "cose_sign1", jsonName: "coseSign1", kind: "bytes" },
      { name: "public_key", jsonName: "publicKey", kind: "bytes" },
      { name: "max_cose_sign1_bytes", jsonName: "maxCoseSign1Bytes", kind: "u64" },
      { name: "max_detached_payload_bytes", jsonName: "maxDetachedPayloadBytes", kind: "u64" },
      { name: "require_kid", jsonName: "requireKid", kind: "bool" },
      { name: "allowed_algorithms", jsonName: "allowedAlgorithms", kind: "repeated_enum", enumName: "CoseSignatureAlgorithm" },
      { name: "external_aad", jsonName: "externalAad", kind: "bytes" },
      { name: "expected_kid", jsonName: "expectedKid", kind: "bytes" },
    ],
  ],
  [
    "CoseSign1VerifyDetachedRequest",
    [
      { name: "cose_sign1", jsonName: "coseSign1", kind: "bytes" },
      { name: "payload", jsonName: "payload", kind: "bytes" },
      { name: "public_key", jsonName: "publicKey", kind: "bytes" },
      { name: "max_cose_sign1_bytes", jsonName: "maxCoseSign1Bytes", kind: "u64" },
      { name: "max_detached_payload_bytes", jsonName: "maxDetachedPayloadBytes", kind: "u64" },
      { name: "require_kid", jsonName: "requireKid", kind: "bool" },
      { name: "allowed_algorithms", jsonName: "allowedAlgorithms", kind: "repeated_enum", enumName: "CoseSignatureAlgorithm" },
      { name: "external_aad", jsonName: "externalAad", kind: "bytes" },
      { name: "expected_kid", jsonName: "expectedKid", kind: "bytes" },
    ],
  ],
  [
    "CoseSign1VerifyResult",
    [
      { name: "payload", jsonName: "payload", kind: "bytes" },
      { name: "algorithm", jsonName: "algorithm", kind: "enum", enumName: "CoseSignatureAlgorithm" },
      { name: "kid", jsonName: "kid", kind: "bytes" },
    ],
  ],
  [
    "CoseKeyFromPublicBytesRequest",
    [
      { name: "algorithm", jsonName: "algorithm", kind: "message", messageName: "CoseAlgorithmIdentifier" },
      { name: "public_key", jsonName: "publicKey", kind: "bytes" },
    ],
  ],
  ["CoseKeyBytesRequest", [{ name: "cose_key", jsonName: "coseKey", kind: "bytes" }]],
  ["CoseKeyBytesResult", [{ name: "key_bytes", jsonName: "keyBytes", kind: "bytes" }]],
  [
    "CoseMultikeyToCoseKeyRequest",
    [{ name: "multikey", jsonName: "multikey", kind: "string" }],
  ],
  ["CoseMultikeyResult", [{ name: "multikey", jsonName: "multikey", kind: "string" }]],
  [
    "CoseMlKemEncryptRequest",
    [
      { name: "kem_algorithm", jsonName: "kemAlgorithm", kind: "enum", enumName: "CoseKemAlgorithm" },
      {
        name: "content_algorithm",
        jsonName: "contentAlgorithm",
        kind: "enum",
        enumName: "CoseContentEncryptionAlgorithm",
      },
      { name: "recipient_public_key", jsonName: "recipientPublicKey", kind: "bytes" },
      { name: "recipient_kid", jsonName: "recipientKid", kind: "bytes" },
      { name: "plaintext", jsonName: "plaintext", kind: "bytes" },
      { name: "external_aad", jsonName: "externalAad", kind: "bytes" },
      { name: "supp_priv_info", jsonName: "suppPrivInfo", kind: "bytes" },
      { name: "has_supp_priv_info", jsonName: "hasSuppPrivInfo", kind: "bool" },
    ],
  ],
  [
    "CoseMlKemEncryptResult",
    [{ name: "cose_encrypt", jsonName: "coseEncrypt", kind: "bytes" }],
  ],
  [
    "CoseMlKemDecryptRequest",
    [
      { name: "cose_encrypt", jsonName: "coseEncrypt", kind: "bytes" },
      { name: "recipient_private_key", jsonName: "recipientPrivateKey", kind: "bytes" },
      { name: "expected_recipient_kid", jsonName: "expectedRecipientKid", kind: "bytes" },
      { name: "external_aad", jsonName: "externalAad", kind: "bytes" },
      { name: "supp_priv_info", jsonName: "suppPrivInfo", kind: "bytes" },
      { name: "has_supp_priv_info", jsonName: "hasSuppPrivInfo", kind: "bool" },
    ],
  ],
  [
    "CoseMlKemDecryptResult",
    [
      { name: "plaintext", jsonName: "plaintext", kind: "bytes" },
      {
        name: "content_algorithm",
        jsonName: "contentAlgorithm",
        kind: "enum",
        enumName: "CoseContentEncryptionAlgorithm",
      },
      { name: "kem_algorithm", jsonName: "kemAlgorithm", kind: "enum", enumName: "CoseKemAlgorithm" },
      { name: "mode", jsonName: "mode", kind: "enum", enumName: "CoseMlKemMode" },
      { name: "recipient_kid", jsonName: "recipientKid", kind: "bytes" },
    ],
  ],
]) {
  generatedText = hardenSensitiveDeserialize(generatedText, name, fields);
}
generatedText = hardenSecretMessage(
  generatedText,
  "CoseSign1CreateDetachedRequest",
  '            .field("private_key", &self.private_key)',
);
generatedText = hardenSecretMessage(
  generatedText,
  "CoseKeyFromPrivateBytesRequest",
  '            .field("private_key", &self.private_key)',
);
for (const fieldName of [
  "key_bytes",
  "cose_key",
  "cose_sign1",
  "kid",
  "payload",
  "private_key",
  "public_key",
  "external_aad",
  "expected_kid",
  "cose_encrypt",
  "plaintext",
  "recipient_public_key",
  "recipient_private_key",
  "recipient_kid",
  "expected_recipient_kid",
  "supp_priv_info",
  "multikey",
]) {
  generatedText = redactDebugBytes(generatedText, fieldName);
}
for (const [name, fieldNames] of [
  // The top-level request owns a nested oneof that can contain private keys or
  // plaintext. Its child messages wipe their declared fields; this owner must
  // additionally wipe length-delimited unknown fields retained by Buffa.
  ["CoseOperationRequest", []],
  // Versioned result wrappers own nested messages whose sensitive scalar
  // fields have dedicated wipe paths. The wrappers still need unknown-field
  // cleanup so future or malicious length-delimited values cannot linger.
  ["CoseOperationResponseV2", []],
  ["CoseOperationResult", []],
  ["CoseSign1CreateRequest", ["payload", "private_key", "kid", "external_aad"]],
  ["CoseSign1CreateDetachedRequest", ["payload", "private_key", "kid", "external_aad"]],
  ["CoseSign1CreateResult", ["cose_sign1"]],
  ["CoseSign1VerifyRequest", ["cose_sign1", "public_key", "external_aad", "expected_kid"]],
  ["CoseSign1VerifyDetachedRequest", ["cose_sign1", "payload", "public_key", "external_aad", "expected_kid"]],
  ["CoseSign1VerifyResult", ["payload", "kid"]],
  ["CoseKeyFromPublicBytesRequest", ["public_key"]],
  ["CoseKeyFromPrivateBytesRequest", ["private_key", "public_key"]],
  ["CoseKeyBytesRequest", ["cose_key"]],
  ["CoseKeyBytesResult", ["key_bytes"]],
  ["CoseMultikeyToCoseKeyRequest", ["multikey"]],
  ["CoseMultikeyResult", ["multikey"]],
  [
    "CoseMlKemEncryptRequest",
    [
      "recipient_public_key",
      "recipient_kid",
      "plaintext",
      "external_aad",
      "supp_priv_info",
    ],
  ],
  ["CoseMlKemEncryptResult", ["cose_encrypt"]],
  [
    "CoseMlKemDecryptRequest",
    [
      "cose_encrypt",
      "recipient_private_key",
      "expected_recipient_kid",
      "external_aad",
      "supp_priv_info",
    ],
  ],
  ["CoseMlKemDecryptResult", ["plaintext", "recipient_kid"]],
]) {
  generatedText = hardenByteFieldsOnDrop(generatedText, name, fieldNames);
}
for (const fieldName of [
  "key_bytes",
  "cose_key",
  "cose_sign1",
  "kid",
  "payload",
  "private_key",
  "public_key",
  "external_aad",
  "expected_kid",
  "cose_encrypt",
  "plaintext",
  "recipient_public_key",
  "recipient_private_key",
  "recipient_kid",
  "expected_recipient_kid",
  "supp_priv_info",
  "multikey",
]) {
  generatedText = generatedText.replaceAll(
    `        self.${fieldName}.clear();`,
    `        ::zeroize::Zeroize::zeroize(&mut self.${fieldName});`,
  );
}
generatedText = generatedText.replaceAll(
  "        self.__buffa_unknown_fields.clear();",
  "        __reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);",
);

// ProtoJSON rejects unknown fields by default. Buffa's generated serde derives
// and oneof visitors currently accept them, so harden both forms here. This is
// boundary validation, not a compatibility policy: callers must not be able to
// misspell a security-relevant field and receive a successful defaulted
// operation.
generatedText = generatedText.replaceAll(
  "#[serde(default)]",
  "#[serde(default, deny_unknown_fields)]",
);
const ignoredUnknownField = `                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }`;
const strictUnknownField = `                        _ => {
                            return Err(serde::de::Error::custom("unknown field"));
                        }`;
const ignoredUnknownFieldCount =
  generatedText.split(ignoredUnknownField).length - 1;
const strictUnknownFieldCount = generatedText.split(strictUnknownField).length - 1;
if (
  ignoredUnknownFieldCount !== oneofCount &&
  !(ignoredUnknownFieldCount === 0 && strictUnknownFieldCount === oneofCount)
) {
  fail(
    `${generated} expected ${oneofCount} generated oneof unknown-field branches, found ${ignoredUnknownFieldCount}`,
  );
}
generatedText = generatedText.replaceAll(
  ignoredUnknownField,
  strictUnknownField,
);
// Buffa's enum visitors otherwise reflect attacker-controlled numeric values
// into allocated error strings. Fixed diagnostics keep boundary failures
// deterministic and avoid carrying untrusted input into logs.
generatedText = generatedText.replaceAll(
  `::serde::de::Error::custom(
                            ::buffa::alloc::format!("enum value {v} out of i32 range"),
                        )`,
  `::serde::de::Error::custom("enum value out of i32 range")`,
);
generatedText = generatedText.replaceAll(
  `::serde::de::Error::custom(
                            ::buffa::alloc::format!("unknown enum value {v32}"),
                        )`,
  `::serde::de::Error::custom("unknown enum value")`,
);
if (generatedText.includes("::buffa::alloc::format!(")) {
  fail(`${generated} still contains formatted ProtoJSON errors`);
}

const generatedPaths = [generated, generatedView, oneof];
const idempotencyBefore = checkIdempotent
  ? new Map(generatedPaths.map((path) => [path, readFileSync(path)]))
  : null;
writeFileSync(generated, generatedText);

let generatedViewText = readFileSync(generatedView, "utf8");
for (const messageName of sensitiveScalarMessageNames) {
  generatedViewText = hardenBorrowedViewDebug(generatedViewText, messageName);
}
writeFileSync(generatedView, generatedViewText);

const oneofText = readFileSync(oneof, "utf8");
if (!oneofText.includes("    #[derive(Clone, PartialEq, Debug)]\n    pub enum Operation {")) {
  fail(`${oneof} is missing the Buffa-required Clone derive for Operation`);
}

if (idempotencyBefore !== null) {
  for (const [path, before] of idempotencyBefore) {
    if (!before.equals(readFileSync(path))) {
      fail("generated COSE protobuf hardening is not idempotent");
    }
  }
}
