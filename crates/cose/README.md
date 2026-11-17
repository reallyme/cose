<div align="center">

# ReallyMe COSE

**CBOR Object Signing and Encryption for Identity**

[![Rust CI](https://github.com/reallyme/cose/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/reallyme/cose/actions/workflows/rust-ci.yml)
[![reallyme-cose](https://img.shields.io/crates/v/reallyme-cose?label=reallyme-cose&color=2563eb)](https://crates.io/crates/reallyme-cose)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](https://github.com/reallyme/cose/blob/main/SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE)

</div>

`reallyme-cose` is a focused COSE layer for identity systems that need
COSE_Sign/Sign1, COSE_Mac/Mac0, COSE_Encrypt/Encrypt0, COSE_Key/KeySet,
RFC 9338 countersignatures, deterministic `kid` derivation, and Multikey interop
with explicit algorithm and profile selection. It builds on
`reallyme-crypto` and `reallyme-codec` to provide strict protected-header
validation, explicit algorithm/key binding, typed non-PII errors, deterministic
CBOR checks, resource limits, and portable conformance vectors for SDK and
protocol implementations.

## Install

```sh
cargo add reallyme-cose
```

The default `native` feature enables the Buffa-generated operation contract,
signing, verification, key validation, HMAC, AES-GCM, and ML-KEM
encryption through `reallyme-crypto`. For `wasm32-unknown-unknown`,
use `default-features = false, features = ["wasm"]`.
Without a runtime lane, the key, Multikey, policy, algorithm-mapping, and CBOR
helper APIs still compile, but operations requiring cryptographic key validation
return `UnsupportedAlgorithm`; signing and encryption APIs are not exported.

Both runtime lanes include the generated contract and its typed, protobuf and
ProtoJSON entrypoints. The explicit `wire` feature remains available for existing
feature recipes:

```toml
reallyme-cose = { version = "0.3.0", features = ["wire"] }
```

When default features are disabled, pair `wire` with an explicit runtime lane,
for example `features = ["native", "wire"]` for native Rust or
`features = ["wasm", "wire"]` for `wasm32-unknown-unknown`.
The `wire` feature is intentionally non-additive: enabling `wire` alone fails
closed because operation adapters must never compile without a selected runtime.

## Explicit signed-container contracts

The `containers` Rust module adds explicit ISO 2021, pinned edition-2 DIS and
strict RFC 9360 contracts: certificate headers and protected SHA-256 x5t,
issuer/device/reader and ReaderAuthAll content, signed revocation/VICAL/RICAL
containers, original peer-key representations, and opaque signing capabilities.
It preserves exact authenticated bytes and distinct wire registrations. Trust,
payload schemas, protocol negotiation and HPKE remain external boundaries.
See the [clause/API/test and provider matrix](https://github.com/reallyme/cose/blob/main/docs/signed-container-contracts.md)
for source baselines, feature recipes, validation and remaining provider gaps.
These working-tree additions are not a claim of complete reader conformance.

## Workspace Layout

The repository follows the same workspace conventions as ReallyMe Crypto and
ReallyMe Codec:

```text
crates/
├── cose/       public COSE facade, semantic operations, tests, and benchmarks
└── proto/      protobuf schema and generated Buffa boundary types
docs/           versioned scope and performance records
fuzz/           cargo-fuzz targets and usage instructions
scripts/        generation, policy, and release-readiness automation
tools/          independent vector audit and golden-vector generation
vectors/        portable classical and post-quantum conformance vectors
```

## Standards Profile

This crate implements a focused COSE profile over:

- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html), for COSE structures,
  protected and unprotected header maps, COSE_Sign1, detached COSE_Mac0,
  Sig_structure and MAC_structure construction,
  COSE_Key structure, key identifiers, and CBOR encoding restrictions.
- [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html), for initial COSE
  algorithm identifiers, key types, curve identifiers, and key-parameter labels.
- [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html), for ML-DSA algorithm
  registrations and AKP COSE_Key encoding.

`reallyme-cose` handles COSE_Key construction and parsing, supported
alg/kty/crv mapping, key identifier policy, deterministic CBOR boundary checks,
and the structural COSE_Sign1 parsing needed by mdoc, attestation, credential,
and wallet code. Signing, verification, hashing, and key generation remain in
`reallyme-crypto`.

The exact COSE signature registration is represented by
`CoseSignatureAlgorithm`, independently of the cryptographic primitive selector
`Algorithm`. This distinction preserves ES256 (`-7`) and ESP256 (`-9`) as
different protocol identities even though both execute with P-256 and SHA-256.
WebAuthn ceremony, authenticator-data, client-data, origin, challenge, and
relying-party validation remain the responsibility of a WebAuthn implementation;
this crate supplies the strict COSE key and algorithm boundary it can consume.
The protobuf contract exposes `ES256` and `ESP256` as separate stable enum
values. COSE_Key result messages report the exact validated signature
registration when the key's `alg` parameter is present. A supported signature
key with omitted `alg` reports no exact registration. Sign1 verification results
include `exact_signature_algorithm` while retaining the existing `algorithm`
field and its numeric behavior for older clients. Generated SDKs therefore do not need to reparse CBOR or infer
an algorithm from the curve.

The generic signing COSE_Key parser and encoder require RFC 8949 core
deterministic map ordering, including nested extension maps. The separate
[`AgreementKey` contract](https://github.com/reallyme/cose/blob/main/docs/agreement-keys.md) accepts unsorted unique public
COSE_Key maps, preserves their exact bytes, and constructs agreement keys without
a signature algorithm. Callers select explicit curve and point-encoding policies;
reader/device role assignment remains outside COSE. Public keys are normalized before deterministic
`kid` derivation. Verification intentionally also accepts other map
orderings permitted by RFC 9052: the received protected-header byte string is
authenticated exactly as received and is never decoded and re-encoded before
signature, MAC, or AEAD verification. Duplicate labels and other profile violations
still fail closed.

## Quick Start

This example generates its key pair with `reallyme-crypto`, so add that direct
dependency alongside `reallyme-cose`:

```toml
reallyme-crypto = { version = "0.4.2", default-features = false, features = ["native", "dispatch", "ed25519"] }
```

```rust
use reallyme_cose::{cose_sign1, cose_verify1_with_policy, Algorithm, CoseError, CosePolicy};
use reallyme_crypto::dispatch::generate_keypair;

fn sign_and_verify() -> Result<(), CoseError> {
    let (public_key, private_key) = generate_keypair(Algorithm::Ed25519)
        .map_err(|_| CoseError::Crypto)?;
    let kid = b"example-key";

    let cose_bytes = cose_sign1(Algorithm::Ed25519, b"payload", &private_key, Some(kid))?;
    let policy = CosePolicy::new()
        .with_require_kid(true)
        .allow_algorithm(Algorithm::Ed25519);

    let verified = cose_verify1_with_policy(&cose_bytes, &policy, |algorithm, requested_kid| {
        (algorithm == Algorithm::Ed25519 && requested_kid == kid).then(|| public_key.clone())
    })?;
    assert_eq!(verified.payload.as_slice(), b"payload");
    assert_eq!(verified.alg, Algorithm::Ed25519);
    assert_eq!(verified.kid.as_slice(), kid);
    Ok(())
}
```

The same example is compile-checked as the crate-level doc example.

## Signing And Verification Options

COSE_Sign1 encoders emit untagged messages by default. Use the tagged helpers
or `CoseSign1EncodeOptions` when an integration expects the registered
COSE_Sign1 root tag (18). These snippets use the `private_key`, `public_key`,
and `kid` from the quick-start example:

```rust
use reallyme_cose::{
    cose_sign1_with_options, Algorithm, CoseSign1EncodeOptions, CoseType,
};

let cose = cose_sign1_with_options(
    Algorithm::Ed25519,
    b"payload",
    &private_key,
    Some(kid),
    CoseSign1EncodeOptions::tagged()
        .with_protected_type(CoseType::MediaType("application/statuslist+cwt".to_owned()))
        .with_max_cose_sign1_bytes(32 * 1024),
)?;
```

Policy-aware verification keeps common platform requirements at the byte API
boundary. `cose_verify1_with_policy` and `cose_verify1_detached_with_policy`
can require `kid`, restrict accepted algorithms, tighten byte limits,
and return verified metadata:

```rust
use reallyme_cose::{cose_verify1_with_policy, Algorithm, CosePolicy};

let policy = CosePolicy::new()
    .with_require_kid(true)
    .with_require_tagged_sign1(true)
    .allow_algorithm(Algorithm::Ed25519)
    .with_max_cose_sign1_bytes(32 * 1024);

let verified = cose_verify1_with_policy(&cose, &policy, |algorithm, requested_kid| {
    (algorithm == Algorithm::Ed25519 && requested_kid == kid).then(|| public_key.clone())
})?;
assert_eq!(verified.alg, Algorithm::Ed25519);
assert_eq!(
    verified.cose_type,
    Some(reallyme_cose::CoseType::MediaType(
        "application/statuslist+cwt".to_owned(),
    )),
);
```

For P-256 integrations, use `allow_cose_algorithm(CoseSignatureAlgorithm::Es256)`
or `allow_cose_algorithm(CoseSignatureAlgorithm::Esp256)` to restrict the exact
registration. `allow_algorithm(Algorithm::P256)` permits both registrations;
when both allow-lists are populated, an input must satisfy both.

### Non-exportable signing keys

Applications that keep private keys in a secure enclave, keystore, HSM, or
another provider-owned boundary implement `CoseSigner` and call
`cose_sign1_with_signer` or `cose_sign1_detached_with_signer`. The provider
receives the exact, bounded COSE `Sig_structure`; private key bytes never enter
the COSE API. Provider failures use the fixed `CoseSignerError` enum, and the
COSE layer validates and normalizes the returned signature before encoding it.

The provider declares its primitive through `CoseSigner::algorithm` and can
override `CoseSigner::cose_algorithm` when the exact registration differs from
the legacy fully specified default. P-256, P-384, and P-521 providers return
DER signatures. Secp256k1 providers return 64-byte `r || s`; Ed25519 and ML-DSA
providers return their fixed-width signature bytes. Providers must return
signatures in a `Zeroizing<Vec<u8>>` owner and must not include key handles, platform exception
text, or user data in errors.

### Sensitive result ownership

Sensitive native results retain wipe-on-drop ownership:
`derive_kid_from_cose_key_public` returns `Zeroizing<Vec<u8>>`, and
`cose_key_to_multikey` returns `Zeroizing<String>`. Keep those owners intact
instead of converting them into ordinary `Vec` or `String` values. `CoseKey`
is also a wipe-on-drop owner and is marked `must_use`.

ML-KEM request values are non-exhaustive and constructed with
`CoseMlKemEncryptRequest::new` or `CoseMlKemDecryptRequest::new`; their fields
are deliberately not public struct-literal surface. Use
`with_supp_priv_info` when replacing the optional private KDF context.

## Supported Features

- COSE_Sign1 with attached payloads.
- COSE_Sign1 with detached payloads.
- Explicit external AAD for attached and detached COSE_Sign1 signing and
  verification. Verification fails authentication when the supplied AAD does
  not exactly match the bytes used for signing.
- COSE_Sign1 signing can emit either untagged messages or messages carrying the
  registered COSE_Sign1 root tag (18) through `cose_sign1_tagged`,
  `cose_sign1_detached_tagged`, or `CoseSign1EncodeOptions`.
- RFC 9596 protected `typ` header label 16 with bounded text media types or
  unsigned CoAP Content-Format identifiers. Verified metadata returns the
  authenticated `CoseType` value.
- Profile-specific signing carries a bounded RFC 9360 `x5chain` certificate
  path in header label 33 through `CoseSign1EncodeOptions`. Placement defaults
  to the protected header. Profiles that require the unprotected header, such
  as mdoc issuer authentication, select
  `with_x5chain_header_placement(X5ChainHeaderPlacement::Unprotected)`.
  The protobuf `x5chain_header_placement` option preserves the protected default
  when unspecified. Duplicate x5chain labels across either header bucket are
  rejected. The `cose_verify1_with_x5chain` API verifies the signature using
  the public key returned by the caller's resolver; that resolver must validate
  the certificates and trust chain before returning the key. It accepts only a
  protected path by default. An unprotected path is not covered by the
  signature, so accepting one requires
  `CosePolicy::with_allow_unprotected_x5chain(true)`; the verified result
  reports the placement. Ordinary verification rejects this extension.
- Ed25519, ES256 (`-7`), ESP256 (`-9`), ESP384 (`-51`), ESP512 (`-52`),
  ES256K (`-47`), ML-DSA-44, ML-DSA-65, and ML-DSA-87 signing using their
  COSE registrations.
- EdDSA (`-8`), ES384 (`-35`), ES512 (`-36`), and unknown algorithm
  registrations are unsupported. They are never inferred from key shape.
- ECDSA signatures on the COSE wire use fixed-width `r || s` encoding;
  DER is accepted only at the NIST-curve signing-provider boundary, not as
  a COSE signature.
- **High-S ECDSA is accepted for P-256, P-384 and P-521; secp256k1 enforces
  low-S.** This is permitted by [RFC 9053 section 2.1](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1).
  Both `(r, s)` and `(r, n-s)` can verify for the same message and key, making
  ECDSA signatures malleable. **Never deduplicate messages or detect replays
  using a hash of the COSE bytes.** Use a stable authenticated message identity
  within the application's protocol context.
- Verification accepts untagged COSE_Sign1 input and input carrying the
  registered COSE_Sign1 tag (18).
- `cose_verify1_with_policy` and `cose_verify1_detached_with_policy` enforce
  `CosePolicy` at the byte API boundary, including `kid` requirements,
  required COSE_Sign1 tag 18, exact protected `typ`, algorithm allow-lists,
  and configurable byte limits.
- `cose_verify1_with_metadata` and policy-aware verification return verified
  payload, algorithm, `kid`, and RFC 9596 `typ` metadata so callers do not need
  to reparse COSE after successful verification. Protobuf verification exposes
  the same `typ` metadata and accepts exact-type and tag-18 requirements.
- Verification binds the protected header bytes exactly as received, per
  RFC 9052 §4.4.
- COSE_Key public/private construction and extraction for supported signing keys.
  Private construction requires the corresponding public key and validates the
  pair before the key can enter the typed API.
- Public `kid` derivation hashes the canonical public COSE_Key, including its
  algorithm binding. A key without `alg` uses the suite's documented default
  registration for this purpose; for P-256 that is ESP256 (`-9`). The same
  point explicitly bound to ES256 (`-7`) has a different `kid`.

- EC2 public-key construction uses the compact RFC 9053 `y`-sign form by
  default. Profiles that require full affine coordinates can opt into
  `CoseEc2PointEncoding::FullCoordinates`; the protobuf field has the same
  explicit policy, with an omitted value preserving the compact default.
  Compact and full-coordinate encodings derive the same canonical public-key
  `kid`, so a representation choice does not change key identity.
- One-recipient `COSE_Encrypt` and `COSE_Recipient` processing for
  ML-KEM-512, ML-KEM-768, and ML-KEM-1024, with direct KMAC256 derivation or
  the fixed ML-KEM-512+A128KW, ML-KEM-768+A192KW, and
  ML-KEM-1024+A256KW key-wrap profiles.
- AES-128-GCM, AES-192-GCM, and AES-256-GCM protected content algorithms for
  every supported ML-KEM recipient profile.
- Guarded COSE_Key, COSE_Sign1, and COSE_Encrypt parsers retain the decoded
  CBOR tree under a recursive wipe owner while semantic fields are copied
  into their profile-specific wipe-on-drop owners. Rejected parses therefore wipe
  partially constructed payload, ciphertext, identifier, header, and key
  buffers. The public `CoseKey` owner also wipes private parameters,
  identifiers, base-IV material, and rejected text/byte extension owners.
  Private-key extraction and verified payloads use zeroizing return buffers.
- COSE_Key public conversion for X25519 key-agreement keys.
- COSE_Key to Multikey and Multikey to COSE_Key conversion, including the
  ReallyMe ML-KEM-512/768/1024 AKP profiles. ML-KEM uses the registered draft
  Multicodec names `mlkem-512-pub`, `mlkem-768-pub`, and `mlkem-1024-pub` with
  the stable ReallyMe private-use COSE algorithm identifiers documented below.
- `kid = SHA-256(canonical algorithm-bound public-only COSE_Key)` derivation.
- Portable classical and PQ vectors in `vectors/cose-sign1*.json`
  and `vectors/cose-key*.json`. The PQ suites cover ML-DSA-44/65/87
  Sign1 plus ML-DSA and ML-KEM AKP COSE_Key/Multikey round trips. ECDSA vectors
  remain the cross-lane contract for fixed-width `r || s` signatures. Any
  Swift, Kotlin, TypeScript, and other SDK implementations must reject DER signatures
  at the COSE boundary.

An empty private-key argument to a signing or construction API yields
`MissingPrivateKey`. Extracting a private component from a public-only
COSE_Key yields `MissingKeyMaterial`. A provider's `InvalidMessage` report is
treated as an operational crypto failure because the COSE layer constructed
the bounded message supplied to that provider.

## ISO/IEC 18013-5:2021 Signature Verification

The explicit `iso18013` module verifies original ES256 (`-7`), ES384 (`-35`),
ES512 (`-36`), and EdDSA (`-8`) registrations with named key curves. It keeps
the modern defaults and exact-registration types unchanged. Each request
requires an exact algorithm/curve allowlist, a trusted verifier, and an issuer,
device, or reader content mode. Issuer content is attached; device and reader
content is detached. External AAD is always empty and protected bytes are
preserved exactly.

The built-in `Iso18013CryptoVerifier` executes ES256/P-256, ES384/P-384,
ES512/P-521, and EdDSA/Ed25519 in native and WASM. Other compatible pairs,
including brainpool and Ed448, fail with `ProviderUnavailable` until a matching
production provider is supplied through `Iso18013Verifier`. Registration and
curve recognition do not imply complete ISO reader coverage. Production crypto
operations remain owned by `reallyme-crypto`.

See the [ISO signature profile and provider matrix](https://github.com/reallyme/cose/blob/main/docs/iso18013-signature-profile.md)
for key import, exact byte preservation, provider integration, errors, limits,
independent vectors, and the separate format, trust, and reader responsibilities.

## Detached COSE_Mac0 Verification

`cose_verify_mac0_detached` implements RFC 9052 §§6.2–6.3 for HMAC 256/64
(`4`), 256/256 (`5`), 384/384 (`6`), and 512/512 (`7`). Both untagged
messages and a single outer tag `17` are accepted. The payload slot must be
CBOR null. The expected payload, external AAD (including an empty slice),
exact algorithm allowlist, and protected direct key are explicit inputs.
An empty allowlist rejects every algorithm. This API is available in both
`native` and `wasm`; its generated operation is `mac0_verify_detached` (`4000`).

```rust
use reallyme_cose::{
    cose_verify_mac0_detached, CoseMac0Error, CoseMac0Limits,
    CoseMac0VerifyRequest, CoseMacAlgorithm, CoseMacKey, VerifiedDetachedCoseMac0,
};
use zeroize::Zeroizing;

fn verify_detached(
    encoded: &[u8],
    expected_payload: &[u8],
    external_aad: &[u8],
    imported_key: Zeroizing<Vec<u8>>,
) -> Result<VerifiedDetachedCoseMac0, CoseMac0Error> {
    let key = CoseMacKey::new(CoseMacAlgorithm::Hmac256_256, imported_key)?;
    cose_verify_mac0_detached(
        CoseMac0VerifyRequest {
            encoded,
            detached_payload: expected_payload,
            external_aad,
            allowed_algorithms: &[CoseMacAlgorithm::Hmac256_256],
            limits: CoseMac0Limits::default(),
        },
        &key,
    )
}
```

Add `zeroize = "1.9.1"` when importing key bytes this way. Direct keys must
have the full underlying hash output length: 32, 48, or 64 bytes. A 256/64 key
also requires 32 bytes and is bound specifically to registration `4`; it cannot
be used for registration `5`. Keys cannot be exported, cloned, or formatted.
The consumed import buffer, primitive key, and secrecy wrapper wipe on drop.

The verifier authenticates `["MAC0", received_protected_bytes, external_aad,
expected_payload]` through `reallyme-crypto`. It never normalizes or re-encodes
the protected byte string. Full tags use the primitive verifier; registration
`4` uses left truncation and the library's constant-time comparison. Each
registration requires its exact tag length. AES-CBC-MAC and other unimplemented
registrations fail closed.

`alg` must be a protected integer. Labels must be unique within and across
header buckets. `crit` must be protected, nonempty, unique, and reference
present protected fields; only `alg` and `kid` critical semantics are supported.
Other noncritical extensions are preserved as authenticated bytes without
interpreting their application semantics. HMAC IV and countersignature headers
are rejected. Content types accept unsigned identifiers or bare RFC 6838 media
types, without MIME parameters. Applications must enforce their own content
semantics. An unprotected `kid` is only a transport hint: it never selects the
key and never appears in the authenticated result.

Results expose the authenticated exact algorithm, original protected bytes,
and protected `kid` only. Their owned buffers wipe on drop and have no formatting
or serialization implementations. Payloads and keys are never returned. Errors
contain only a fixed `CoseMac0ErrorReason`, with no input or backend text.
Callers remain responsible for wiping their original encoded input, payload,
AAD, and earlier key copies when those contain sensitive data.

Hard limits are 65,536 encoded bytes, 1,048,576 payload bytes, 65,536 AAD bytes,
32 parameters per header map, 1,024 items per collection, and 32 CBOR nesting
levels per decoded CBOR boundary. `CoseMac0Limits` can lower the byte limits;
raising its fields cannot bypass hard maxima. Indefinite lengths, nonpreferred
integer/length widths, unsupported tags and simple values, malformed structures,
duplicate labels, and trailing data are rejected before crypto verification.

The MAC tests pin independent COSE Working Group HMAC vectors from
[revision 53c9d634](https://github.com/cose-wg/Examples/tree/53c9d634333bb4f529d78f5980fffa2667ee2c12)
for all four registrations. They retain the published tags when detaching the
payload and separately pin a Python stdlib HMAC vector with external AAD and
an unsorted protected header map.

## Protobuf Wire Boundary

The protobuf schema defines every public operation. ReallyMe Buffa 0.1.1 generates its
request/result types, policy selectors, operation discriminants and error codes.
Use `api::contract` for those definitions and `api::execute` for typed Rust
execution. `api::execute_with_providers` accepts explicit application-local
capabilities. `api::execute_with_provider_transport` uses the generated provider
registry and callback messages for non-Rust implementations. Borrowed Rust readers and callback signatures remain thin adapters
to the same semantic operations.

See the [operation and migration matrix](https://github.com/reallyme/cose/blob/main/docs/generated-operation-contract.md)
for all 34 operations, preserved wire identifiers, callback/handle contracts,
ownership and parity coverage.

The 0.3.0 [presence migration](https://github.com/reallyme/cose/blob/main/docs/protobuf-presence-migration.md)
replaces manual flags with optional bytes and enum `UNSPECIFIED` values.

The checked-in schema lives at
`crates/proto/proto/reallyme/cose/v1/cose.proto`. Generated Buffa Rust
types live in the low-level `reallyme-cose-proto` workspace crate, under
`crates/proto`; that crate owns the generated public contract separately from the handwritten
implementation and its lint posture. After editing the schema, regenerate and
format the generated files using the commands in Development Checks, then keep
them checked in. COSE does not currently publish Swift, Kotlin, or
TypeScript packages from this repository. The schema's Swift metadata allows
generated Swift protobuf consumers to use the same wire contract independently.

The wire lane has two layers:

- `reallyme-cose-proto` owns generated request, result, and error message
  types and policy selectors. These are the authoritative public definitions.
  Its generated Rust is hardened after
  `buf generate` so request, result, key, payload, AAD, and `kid` byte fields
  are redacted from `Debug`, zeroized by `clear`, and zeroized on drop. Buffa
  requires generated messages to remain `Clone`; each clone is therefore an
  explicit transient owner with the same wipe-on-drop behavior.
- `reallyme-cose::api` provides typed execution; `reallyme-cose::wire` retains
  executable codec adapters. Both runtime lanes enable these adapters. Use `wire::execute_operation_proto` for protobuf request bytes or
  `wire::execute_operation_proto_json` for generated ProtoJSON requests. Both return a
  binary `CoseOperationResponseV2`, whose outcome is either a structured error
  or an exact operation-specific result variant. Rust-side adapters should use
  `wire::decode_operation_response_for_request`; it rejects a result variant
  that does not match the submitted request. The earlier status-plus-opaque-
  payload compatibility envelope remains unsupported. Operation-specific dispatch
  remains private so the executable boundary has one request and one response
  model.

Executable response bytes are stored in zeroizing owners by the Rust wire
adapter. Generated ProtoJSON uses protobuf enum names
and standard protobuf base64 bytes. Serialization returns a caller-owned JSON
`String` that the library cannot wipe; callers handling private keys, payloads,
AAD, or identifiers should place it in a zeroizing owner and release it as soon
as the transport write completes. Likewise, generated `PartialEq` is a schema
convenience and is not a constant-time secret comparison primitive.

ProtoJSON is provided only by the generated Buffa protobuf types. The native
Rust SDK has no parallel JSON model. `buf.gen.yaml` enables the complete native
cleanup profile, strict JSON fields and local guarded byte/string policies.
Generated messages and oneofs redact Debug and wipe on clear/drop; field owners
also protect replacement, failed decoding and spare capacity. Guarded repeated
collections wipe outgrown allocations, including scalar slots.

Borrowed views and owned-view backing buffers remain separate input owners.
Whole-view JSON export is denied, even for empty views; explicit owned-message
JSON follows the selected field policies. Serialized JSON/protobuf copies and
parser input remain caller-owned. The executable decoder rejects unknown wire
fields before they can be discarded. Direct decoder/transport integrations must
use `DecodeOptions::reject_unknown_fields()` on the original bounded bytes;
a default decoder with storage disabled cannot preserve unknown-field evidence.

See the [Buffa security migration matrix](https://github.com/reallyme/cose/blob/main/docs/buffa-migration.md).
Buffa generates cleanup and fixed standalone enum diagnostics directly.

## ReallyMe ML-KEM COSE Profile

This version encodes ML-KEM recipient profiles with stable ReallyMe
private-use identifiers below `-65536`. These identify the construction
specified here, independently of future standards-track registrations:

| COSE algorithm | ReallyMe identifier |
| --- | ---: |
| ML-KEM-512 direct | `-65537` |
| ML-KEM-768 direct | `-65538` |
| ML-KEM-1024 direct | `-65539` |
| ML-KEM-512+A128KW | `-65540` |
| ML-KEM-768+A192KW | `-65541` |
| ML-KEM-1024+A256KW | `-65542` |
| `ek` recipient header label | `-65543` |

These are COSE integer identifiers and are deliberately independent from the
protobuf enum numbers. The content algorithm is authenticated in the
`COSE_Encrypt` protected header. The exact direct or key-wrap ML-KEM profile and
the mandatory recipient `kid` are authenticated in the `COSE_Recipient`
protected header. The `ek` header carries the ML-KEM ciphertext in the
recipient unprotected map. Tampering with `ek` is detected by ML-KEM
decapsulation and subsequent content or key-wrap authentication; `ek` is not
included in the KDF context.

For DID and Multikey integration, public ML-KEM AKP keys use the draft
Multicodec names `mlkem-512-pub`, `mlkem-768-pub`, and `mlkem-1024-pub`.
Decoding those Multikeys binds them to the corresponding ReallyMe private-use
COSE algorithm identifier; it never guesses a future IANA value.

The envelope and `Enc_structure` follow [RFC 9052 section 5](https://www.rfc-editor.org/rfc/rfc9052.html#section-5).
The private profile's KMAC256 context follows the field layout in
[draft-ietf-jose-pqc-kem-06 section 5.1](https://datatracker.ietf.org/doc/html/draft-ietf-jose-pqc-kem-06#section-5.1),
with PartyUInfo and PartyVInfo omitted. The general
[RFC 9053 section 5.2](https://www.rfc-editor.org/rfc/rfc9053.html#section-5.2)
context includes those fields. The private identifiers above select the
documented KMAC256 construction explicitly.

The ReallyMe profile uses the following construction:

- ML-KEM uses AKP COSE keys. Private import/export uses the 64-octet FIPS 203
  seed `d || z`, and private/public construction cryptographically validates
  the supplied pair.
- The mandatory recipient `kid` is exactly
  `SHA-256(canonical public-only algorithm-bound COSE_Key)`. Encryption rejects
  a caller-supplied identifier that does not identify the recipient public key.
  Decryption deterministically derives the public key from the private
  `d || z` seed and rejects a protected `kid` bound to any other key before
  decapsulation. Arbitrary routing labels are not valid recipient identifiers
  in this profile.
- KMAC256 derives from the ML-KEM shared secret. Its message is the CBOR KDF
  context `[AlgorithmID, SuppPubInfo, ?SuppPrivInfo]`, its customization string
  is empty, and `SuppPubInfo` binds the output length and exact encoded
  recipient protected header.
- Direct mode derives the AES-GCM content-encryption key and requires CBOR
  `nil` (`f6`) as recipient ciphertext. An empty byte string (`h''`) or any
  other present ciphertext is rejected before private-key use and on encoding.
- Key-wrap mode derives only the fixed AES-KW key-encryption key for the KEM
  strength, wraps a fresh random content-encryption key, and carries that
  wrapped key as recipient ciphertext.
- The ML-KEM parameter set and AES-GCM content cipher are independent protocol
  choices. Mixed combinations remain interoperable, but their combined
  security is limited by the weaker component. Applications seeking aligned
  strength should pair ML-KEM-512 with AES-128-GCM, ML-KEM-768 with
  AES-192-GCM, and ML-KEM-1024 with AES-256-GCM.
- External AAD and optional `SuppPrivInfo` must match exactly at decryption.
  AES-KW integrity failures remain distinct from content authentication
  failures.

This initial profile intentionally supports exactly one recipient. Decoding
accepts tagged or untagged `COSE_Encrypt`; encoding emits the registered
`COSE_Encrypt` tag. AKP keys use the base direct identifier in their `alg`
parameter because the same key may be selected by either recipient mode; the
recipient protected `alg` remains the authoritative operation profile.

This version recognizes only the listed ML-KEM identifiers. Supporting any
additional registration requires an explicit profile update; existing
private-use objects must not be silently reinterpreted.

## COSE-Layer Vector Audit

`tools/vector-audit` is a standalone, unpublished Cargo binary that audits the
committed vector JSON with RustCrypto, `ciborium`, and `bs58`. It does not
depend on `reallyme-cose`, `reallyme-crypto`, or `reallyme-codec`, which keeps
the CBOR, COSE, KDF, key-wrap, and Multikey checks independent from production.
It uses the same direct RustCrypto primitive families as production, so
primitive ACVP assurance remains the responsibility of the pinned
`reallyme-crypto` dependency. In addition to COSE_Sign1 and COSE_Key fixtures,
the tool independently parses the ReallyMe
ML-KEM `COSE_Encrypt` maps, repeats deterministic encapsulation and
decapsulation, reconstructs the KMAC256 context, performs RFC 3394 AES-KW
unwrap where applicable, and authenticates the AES-GCM ciphertext. It also
derives every PQ public key directly from its seed, verifies ML-DSA Sign1
signatures through `ml-dsa`, and checks the AKP parameters and Multicodec prefix
without linking the production COSE, Crypto, or Codec crates.

The classical Sign1 suite also contains a fixed Ed25519 signature produced by
Node's OpenSSL-backed implementation over RFC 8032 key material. Suite counts
and exact SHA-256 digests are bound in `vectors/manifest.json`.

`tools/vector-goldens` is the separate maintenance generator for deterministic
ReallyMe fixtures. Its fixed ML-KEM seeds, encapsulation randomness, CEKs, and
nonces are test inputs only; the production encryption API continues to use
operating-system entropy. Regenerated bytes must pass the independent audit
before they are accepted.

```sh
cargo run --manifest-path tools/vector-goldens/Cargo.toml
cargo run --manifest-path tools/vector-audit/Cargo.toml --bin reallyme-cose-vector-audit -- .
```

## General message contracts

The protobuf contract provides bounded creation and authentication operations
for COSE_Sign, COSE_Mac and COSE_Encrypt0; parse/create operations for
COSE_KeySet; and full/abbreviated RFC 9338 countersignatures. Use
`api::contract` for generated requests and `api::execute` for the native typed
entrypoint. Binary protobuf and ProtoJSON use the same semantic implementation.
Every authentication request requires explicit algorithm/suite allowlists and
caller-authorized keys. No trust or identity policy is inferred from headers.

Protected header bytes are authenticated exactly as received. Each family has
its own RFC context and content contract. Detached content is explicit, and
counter attachment preserves all primary fields outside the unprotected map.
These general operations use definite preferred CBOR with received map order;
the existing ISO 2021 Sign1 compatibility profile remains explicitly selected.

See the [clause-to-operation/test matrix](https://github.com/reallyme/cose/blob/main/docs/message-family-support.md),
[Sign](https://github.com/reallyme/cose/blob/main/docs/sign-message-contract.md),
[MAC](https://github.com/reallyme/cose/blob/main/docs/mac-message-contract.md),
[Encrypt0](https://github.com/reallyme/cose/blob/main/docs/encrypt0-contract.md),
[KeySet](https://github.com/reallyme/cose/blob/main/docs/key-set-contract.md), and
[countersignature contracts](https://github.com/reallyme/cose/blob/main/docs/countersignature-contract.md)
for exact limits, supported crypto suites, ownership and failure behavior.

## Unsupported COSE Surface

The following structures and features are not implemented:

- COSE_Mac0 creation or attached-content verification, and AES-CBC-MAC.
- Multi-recipient COSE_Encrypt.
- Critical parameters outside the selected operation's implemented semantics.
- Deprecated RFC 8152 countersignature headers 7 and 9. RFC 9338 operations
  use the distinct headers 11/12 and the required V2 authentication structures.
- Modern COSE_Sign1 content-type and extension headers other than RFC 9596 `typ`,
  because the verified-result API does not expose processing results for those
  semantics.
- Integrity-sensitive fields in unprotected headers. Modern Sign1 requires
  protected `alg` and `kid`; ISO Sign1 and Mac0 permit an unprotected `kid` hint
  without trusting it.
- Indefinite-length CBOR at public byte boundaries.
- Floating-point extension values in the legacy cryptographic COSE_Key import
  path. KeySet sensitive storage can retain codec-validated opaque extensions;
  its public-parameter projection removes them.
- Undefined or unsupported simple values in structural content/key fields;
  detached payload and ciphertext slots require null.
- Root tags other than the matching COSE_Encrypt0 (16), COSE_Mac0 (17),
  COSE_Sign1 (18), full countersignature (19), COSE_Encrypt (96), COSE_Mac (97),
  or COSE_Sign (98) tag. Keys, KeySets and abbreviated counters are untagged.
- X-Wing recipient processing. X-Wing-768 remains represented in the protobuf
  algorithm enum so the wire contract can add an explicit profile without
  renumbering; attempts to use it in an unsupported operation fail closed
  without provider or algorithm fallback.

Unsupported inputs fail closed with typed `CoseError` variants. Error messages
do not include payloads, keys, raw CBOR, or resolver-provided material.

## Resource Limits

Public byte-boundary APIs enforce deterministic limits before COSE structure
decoding:

- COSE_Sign1 input: 65,536 bytes.
- COSE_Key input: 16,384 bytes.
- COSE_Encrypt input: 1,114,112 bytes.
- Detached payload input: 1,048,576 bytes.

The encoded COSE_Sign1 hard maximum is 65,536 bytes. Signing options and
verification policy can tighten this ceiling; larger requested limits are
clamped to the hard maximum. Detached payloads can contain up to 1,048,576
bytes, and Sign1 external AAD has an independent 65,536-byte hard maximum.
A present `CoseByteLimits` message treats zero as a real zero ceiling for each
field. Payload and AAD ceilings are enforced independently for signing and
verification. Larger reports can use detached content within its payload
ceiling.
Importing a verification policy or signing options normalizes the stored
generated limits to these maxima while retaining absent limits and explicit
zero ceilings.

`reallyme_cose::sign1::build_sign1_signature_structure` constructs standalone
RFC 9052 Signature1 authentication input with an explicit complete-output
budget. It preserves protected-header bytes exactly and supports larger
headers and payloads independently of verification-profile limits. The helper
checks the encoded length before reserving output, returns a wiping owner, and
is available without a crypto backend. The protobuf `sign1_signature_structure`
operation (1018) exposes the same construction within the transport envelope
limits.

The default verification policy accepts every supported signature algorithm.
An explicitly configured empty primitive or exact-registration allow-list
rejects every algorithm; `allow_any_algorithm()` opts back into unrestricted
verification. Set an allow-list for verifier surfaces that know their
credential suite. `CosePolicy::require_kid()` is the
separate protected-header presence gate; it does not imply an algorithm
allow-list. Policy and signing-option structs are constructed with builders
rather than public fields so new policy controls can be added without breaking
downstream callers.

The exact-algorithm native verifier variants pass
`(CoseSignatureAlgorithm, protected_kid)` to the key resolver. Use both values
as the lookup identity when a key is registered for a specific COSE algorithm.
The legacy resolver variants, including `cose_verify1_with_x5chain`, pass the
broader cryptographic primitive `Algorithm`; they cannot distinguish ES256
from ESP256. Protobuf verification can bind a supplied key to an exact
registration with `public_key_algorithm`; its algorithm allow-list and
`expected_kid` provide separate policy controls. A legacy wire
`ECDSA_P256_SHA256` allow-list entry denotes ESP256 only; use the `ES256`
entry to permit ES256.

The protobuf operation lane has an independent 2 MiB request-message cap.
Operation-specific hard maxima apply equally to native Rust and protobuf
callers; an envelope limit does not widen the COSE, payload or AAD ceiling.
Generated ProtoJSON requests have a separate 3 MiB input cap to accommodate
base64 and field-name overhead.
ProtoJSON requests must use literal characters rather than JSON escape sequences, including in
base64-encoded secret fields, so decoding does not retain an unwiped escape
scratch buffer. Binary protobuf follows protobuf's last-oneof-member and
repeated-message merge semantics; ProtoJSON rejects duplicate fields. Callers
that require one canonical request encoding should choose one lane and enforce
it before admission.

## 0.3.0 Platform Scope

The `0.3.0` release is intentionally Rust and protobuf only. Its publishable
artifacts are `reallyme-cose-proto` and `reallyme-cose`; the `native` and `wasm`
features are Rust runtime lanes, not platform SDK packages.

The `0.3.0` distribution does not include Swift, Android/Kotlin, Kotlin/JVM,
native C/JNI, or TypeScript/WASM npm packages. Those package formats are not
part of this release's compatibility or support contract.

The protobuf `swift_prefix` option is generation metadata, not a published
Swift package. Likewise, `wasm32-unknown-unknown` is a Rust compilation target,
not an npm package. The exact artifact scope is recorded in
[`docs/platform-scope-0.3.0.json`](https://github.com/reallyme/cose/blob/main/docs/platform-scope-0.3.0.json).

## Development Checks

Internal crates must declare `publish = false` in their own `[package]` section.
The approved public crates explicitly enable publication in their manifests.

The workspace declares Rust 1.100 as its minimum supported version; the development
toolchain is pinned in `rust-toolchain.toml`. Run the repository gate for format,
feature-matrix, lint, test, allocation, WASM runtime, vector, fuzz-build, and
dependency checks after installing the pinned external-type checker:

```sh
bash scripts/install_external_type_checker.sh .local-tools
node scripts/run_pinned_release_readiness.mjs
```

Protobuf regeneration requires Buf 1.73.0 and the ReallyMe Buffa 0.1.1 tools:

```sh
cargo install reallyme-protoc-gen-buffa --version '=0.1.1' --locked
cargo install reallyme-protoc-gen-buffa-packaging --version '=0.1.1' --locked
test "$(protoc-gen-reallyme-buffa --version)" = "protoc-gen-reallyme-buffa 0.1.1"
test "$(protoc-gen-reallyme-buffa-packaging --version)" = "protoc-gen-reallyme-buffa-packaging 0.1.1"
node scripts/generate_cose_contract.mjs
node scripts/run_pinned_release_readiness.mjs --generated-freshness
```

The generation driver requires exact executable names and versions, lints the
schema, runs both local plugins, and emits separate schema-derived compatibility
projections. The driver formats the generated Rust with `rustfmt`. Freshness
regenerates into a temporary directory and compares every output against the
checked-in files.
`node scripts/generate_cose_contract.mjs --check` runs that comparison directly.
CI uses the pinned shared release-readiness runner;
crate publication additionally requires its package-preflight checks. Locally,
`node scripts/run_pinned_release_readiness.mjs` executes the shared package from
the immutable upstream revision pinned in that runner, then runs the repository
gate. It requires npm and network access to retrieve the pinned package.
Use `--policy-only` to check repository policy without the full build and runtime
suite. Fuzzing commands and runtime limits are documented in
[the fuzzing guide](https://github.com/reallyme/cose/blob/main/fuzz/README.md).
The [formal verification guide](https://github.com/reallyme/cose/blob/main/docs/formal-verification.md)
documents the Kani checks, their input bounds, and how to run them locally.

Release readiness requires crates.io dependencies for the published ReallyMe
foundational crates: `reallyme-crypto` `^0.4.2` and `reallyme-codec` `^0.4.3`.
Local `../crypto` or `../codec` path dependencies are not accepted for release.

The package preflight verifies the requested release commit and crate version,
audits committed lockfiles, runs the pinned release-readiness checks, and
inspects and dry-runs the package publication. The release workflow publishes
with the repository's `CARGO_REGISTRY_TOKEN` after the reviewed package
preflight succeeds.

The gate also checks operation routing, typed errors, sensitive-buffer ownership,
and allocation limits. The benchmark asserts named peak-allocation ceilings;
historical measurements for the 0.2.3 dependency set are recorded in
[`docs/performance-baseline-0.2.3.md`](https://github.com/reallyme/cose/blob/main/docs/performance-baseline-0.2.3.md).
Rerun the benchmark to measure a changed implementation or host.

The wasm lane must be checked against `wasm32-unknown-unknown`. A host-target
`cargo check --workspace --no-default-features --features wasm` is intentionally
not the supported command because `reallyme-crypto` exposes its wasm provider
exports only when compiling for `wasm32`. Use `cargo check-wasm`, or run the
equivalent explicit command:

```sh
cargo check --workspace --target wasm32-unknown-unknown --no-default-features --features wasm
```

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

Third-party components retain their own licenses and notices.

## Copyright and Trademarks

Copyright © 2026 by ReallyMe Technologies Limited.

ReallyMe® is a registered trademark of ReallyMe LLC.
