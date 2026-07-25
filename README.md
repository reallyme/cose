<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-cose

[![Rust CI](https://github.com/reallyme/cose/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/reallyme/cose/actions/workflows/rust-ci.yml)
[![reallyme-cose](https://img.shields.io/crates/v/reallyme-cose?label=reallyme-cose&color=2563eb)](https://crates.io/crates/reallyme-cose)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](SECURITY.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

`reallyme-cose` is a focused COSE layer for identity systems that need
COSE_Sign1, COSE_Key, deterministic `kid` derivation, and Multikey interop
without broad COSE structure or algorithm negotiation. It builds on
`reallyme-crypto` and `reallyme-codec` to provide strict protected-header
validation, explicit algorithm/key binding, typed non-PII errors, deterministic
CBOR checks, resource limits, and portable conformance vectors for SDK and
protocol implementations.

## Install

```sh
cargo add reallyme-cose
```

Default features enable COSE signing and verification through `reallyme-crypto`.
With `default-features = false`, the crate still builds the COSE_Key, Multikey,
policy, algorithm-mapping, and CBOR limit helpers, but does not export
crypto-backed signing or verification APIs.

Enable the `wire` feature only for protobuf operation adapters:

```toml
reallyme-cose = { version = "0.2.0", features = ["wire"] }
```

When default features are disabled, pair `wire` with an explicit runtime lane,
for example `features = ["native", "wire"]` for native Rust or
`features = ["wasm", "wire"]` for `wasm32-unknown-unknown`.
The `wire` feature is intentionally non-additive: enabling `wire` alone fails
closed because operation adapters must never compile without a selected runtime.

## Workspace Layout

The repository follows the same workspace conventions as ReallyMe Crypto and
ReallyMe Codec:

```text
crates/
├── cose/       public COSE facade, semantic operations, tests, and benchmarks
└── proto/      protobuf schema and generated Buffa boundary types
docs/           versioned scope and performance records
fuzz/           cargo-fuzz targets and corpora
scripts/        generation, policy, and release-readiness automation
tools/          independent vector audit and golden-vector generation
vectors/        portable classical and post-quantum conformance vectors
```

## Standards Profile

This crate implements a focused COSE profile over:

- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html), for COSE structures,
  protected and unprotected header maps, COSE_Sign1, Sig_structure construction,
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

COSE_Key bytes used for deterministic `kid` derivation follow RFC 8949 core
deterministic map ordering. Verification intentionally also accepts other map
orderings permitted by RFC 9052: the received protected-header byte string is
authenticated exactly as received and is never decoded and re-encoded before
signature or AEAD verification. Duplicate labels and other profile violations
still fail closed.

## Quick Start

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
COSE_Sign1 root tag (18):

```rust
use reallyme_cose::{cose_sign1_with_options, Algorithm, CoseSign1EncodeOptions};

let cose = cose_sign1_with_options(
    Algorithm::Ed25519,
    b"payload",
    &private_key,
    Some(b"example-key"),
    CoseSign1EncodeOptions::tagged().with_max_cose_sign1_bytes(512 * 1024),
)?;
```

Policy-aware verification keeps common platform requirements at the byte API
boundary. `cose_verify1_with_policy` and `cose_verify1_detached_with_policy`
can require `kid`, restrict accepted algorithms, raise or lower byte limits,
and return verified metadata:

```rust
use reallyme_cose::{cose_verify1_with_policy, Algorithm, CosePolicy};

let policy = CosePolicy::new()
    .with_require_kid(true)
    .allow_algorithm(Algorithm::P256)
    .with_max_cose_sign1_bytes(512 * 1024);

let verified = cose_verify1_with_policy(&cose, &policy, |algorithm, kid| {
    resolve_public_key(algorithm, kid)
})?;
assert_eq!(verified.alg, Algorithm::P256);
```

### Non-exportable signing keys

Applications that keep private keys in a secure enclave, keystore, HSM, or
another provider-owned boundary implement `CoseSigner` and call
`cose_sign1_with_signer` or `cose_sign1_detached_with_signer`. The provider
receives the exact, bounded COSE `Sig_structure`; private key bytes never enter
the COSE API. Provider failures use the fixed `CoseSignerError` enum, and the
COSE layer validates and normalizes the returned signature before encoding it.

The provider declares one algorithm through `CoseSigner::algorithm`. ECDSA
providers return their native DER signature; providers for Ed25519 and ML-DSA
return fixed-width signature bytes. Providers must return signatures in a
`Zeroizing<Vec<u8>>` owner and must not include key handles, platform exception
text, or user data in errors.

### Sensitive result ownership

Native APIs retain wipe-on-drop ownership at the public boundary:
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
- Ed25519, P-256, P-384, P-521, secp256k1, ML-DSA-44, ML-DSA-65, and
  ML-DSA-87 signing using their current IANA COSE registrations.
- ECDSA signatures use the fixed-width `r || s` encoding required by
  RFC 9053; DER-encoded ECDSA signatures are rejected.
- Verification accepts untagged COSE_Sign1 input and input carrying the
  registered COSE_Sign1 tag (18).
- `cose_verify1_with_policy` and `cose_verify1_detached_with_policy` enforce
  `CosePolicy` at the byte API boundary, including `kid` requirements,
  algorithm allow-lists, and configurable byte limits.
- `cose_verify1_with_metadata` and policy-aware verification return verified
  payload, algorithm, and `kid` metadata so callers do not need to reparse COSE
  after successful verification.
- Verification binds the protected header bytes exactly as received, per
  RFC 9052 §4.4.
- COSE_Key public/private construction and extraction for supported signing keys.
  Private construction requires the corresponding public key and validates the
  pair before the key can enter the typed API.
- One-recipient `COSE_Encrypt` and `COSE_Recipient` processing for
  ML-KEM-512, ML-KEM-768, and ML-KEM-1024, with direct KMAC256 derivation or
  the fixed ML-KEM-512+A128KW, ML-KEM-768+A192KW, and
  ML-KEM-1024+A256KW key-wrap profiles.
- AES-128-GCM, AES-192-GCM, and AES-256-GCM protected content algorithms for
  every supported ML-KEM recipient profile.
- Guarded COSE_Key, COSE_Sign1, and COSE_Encrypt parsers retain the decoded
  CBOR tree under a recursive wipe owner until every semantic field has moved
  into its profile-specific wipe-on-drop owner. Rejected parses therefore wipe
  partially constructed payload, ciphertext, identifier, header, and key
  buffers. The public `CoseKey` owner also wipes private parameters,
  identifiers, base-IV material, and rejected text/byte extension owners.
  Private-key extraction and verified payloads use zeroizing return buffers.
- COSE_Key public conversion for X25519 key-agreement keys.
- COSE_Key to Multikey and Multikey to COSE_Key conversion, including the
  ReallyMe ML-KEM-512/768/1024 AKP profiles. ML-KEM uses the registered draft
  Multicodec names `mlkem-512-pub`, `mlkem-768-pub`, and `mlkem-1024-pub` while
  retaining ReallyMe private-use COSE algorithm identifiers until IANA assigns
  final values.
- `kid = SHA-256(canonical algorithm-bound public-only COSE_Key)` derivation.
- Portable classical and PQ vectors in `vectors/cose-sign1*.json`
  and `vectors/cose-key*.json`. The PQ suites cover ML-DSA-44/65/87
  Sign1 plus ML-DSA and ML-KEM AKP COSE_Key/Multikey round trips. ECDSA vectors
  remain the cross-lane contract for fixed-width `r || s` signatures. Any
  Swift, Kotlin, TypeScript, and other SDK implementations must reject DER signatures
  at the COSE boundary.

## Protobuf Wire Boundary

The native Rust API remains the primary SDK surface. For service, FFI, generated
SDK, and conformance boundaries, `reallyme-cose` also exposes a generated
protobuf operation lane: request bytes in, result-envelope bytes out, with
structured `CoseError` protobuf bytes on failure.

The checked-in schema lives at
`crates/proto/proto/reallyme/cose/v1/cose.proto`. Generated Buffa Rust
types live in the low-level `reallyme-cose-proto` workspace crate, under
`crates/proto`; that crate is published only so the optional `wire` feature
can remain publishable while generated code and its lint posture stay out of the
handwritten native crate. After editing the schema, run `buf generate` and keep the
generated files checked in. COSE does not currently publish Swift, Kotlin, or
TypeScript packages from this repository. The schema's Swift metadata allows
generated Swift protobuf consumers to use the same wire contract independently.

The wire lane has two layers:

- `reallyme-cose-proto` owns generated request, result, and error message
  types. It is not the normal SDK surface. Its generated Rust is hardened after
  `buf generate` so request, result, key, payload, AAD, and `kid` byte fields
  are redacted from `Debug`, zeroized by `clear`, and zeroized on drop. Buffa
  requires generated messages to remain `Clone`; each clone is therefore an
  explicit transient owner with the same wipe-on-drop behavior.
- `reallyme-cose::wire` owns executable adapters behind the opt-in `wire`
  feature. Use `wire::execute_operation_proto` for protobuf request bytes or
  `wire::execute_operation_proto_json` for generated ProtoJSON requests. Both return a
  binary `CoseOperationResponseV2`, whose outcome is either a structured error
  or an exact operation-specific result variant. Rust-side adapters should use
  `wire::decode_operation_response_for_request`; it rejects a result variant
  that does not match the submitted request. The earlier status-plus-opaque-
  payload compatibility envelope has been removed. Operation-specific dispatch
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
Rust SDK does not define a second ad hoc JSON representation for COSE requests
or results. `buf.gen.yaml` enables both borrowed Buffa views and strict
generated ProtoJSON. The post-generation hardening pass redacts sensitive byte
fields in both owned-message and borrowed-view `Debug` implementations; owned
messages additionally zeroize sensitive buffers on `clear` and drop. Borrowed
views cannot erase caller-owned input and therefore do not claim zeroization.
The executable binary protobuf decoder rejects unknown fields, matching strict
ProtoJSON semantics and preventing opaque length-delimited values from being
retained in generated unknown-field storage. Direct users of sensitive
generated messages also receive recursive unknown-field wiping on `clear` and
drop.

## ReallyMe ML-KEM COSE Profile

The current IANA COSE algorithm registry does not yet assign ML-KEM recipient
algorithm identifiers. To provide interoperable COSE objects now without
occupying or guessing future standards-track values, ReallyMe emits stable
private-use identifiers below `-65536`:

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
recipient unprotected map because its integrity is established by successful
decapsulation, KDF binding, and content or key-wrap authentication.

For DID and Multikey integration, public ML-KEM AKP keys use the draft
Multicodec names `mlkem-512-pub`, `mlkem-768-pub`, and `mlkem-1024-pub`.
Decoding those Multikeys binds them to the corresponding ReallyMe private-use
COSE algorithm identifier; it never guesses a future IANA value. When final
IANA identifiers are assigned, transitional decoding must accept the private
and final identifiers explicitly while encoding policy selects one deliberately.

The profile follows the current COSE ML-KEM draft construction:

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
- Direct mode derives the AES-GCM content-encryption key and encodes a null
  recipient ciphertext.
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

When IANA assigns final identifiers, ReallyMe will add explicit transitional
decoding for the private-use and final identifiers. Existing private-use
objects will not be silently reinterpreted, and emitted identifiers will change
only in a documented profile/version transition.

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

## Unsupported COSE Surface

The following structures and features are not implemented:

- COSE_Mac0, COSE_Mac, and MAC verification.
- COSE_Encrypt0.
- Multi-recipient COSE_Encrypt.
- COSE_Sign multi-signer structures.
- Countersignatures.
- Critical protected headers.
- COSE_Sign1 content-type and extension headers, because the verified-result
  API does not expose processing results for those semantics.
- Integrity-sensitive fields in unprotected headers, including `alg` and `kid`.
- Indefinite-length CBOR at public byte boundaries.
- Floating-point COSE_Key extension values. They are rejected rather than
  accepted without full RFC 8949 preferred-width and canonical-NaN validation.
- Unexpected CBOR tags except a root COSE_Sign1 tag when decoding Sign1 input.
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

The default attached COSE_Sign1 limit is 65,536 bytes. Consumers that need
larger attached reports can opt into a higher limit with
`CoseSign1EncodeOptions::with_max_cose_sign1_bytes` when signing and
`CosePolicy::with_max_cose_sign1_bytes` when verifying. Large application payloads
should still prefer detached signing and enforce transport or application-level
limits before calling this crate.

`CosePolicy::allowed_algorithms()` is intentionally fail-open only when empty: an empty
allow-list means "any algorithm implemented by this crate and accepted by the
COSE_Key/key resolver path." Set at least one allowed algorithm for verifier
surfaces that know their credential suite. `CosePolicy::require_kid()` is the
separate protected-header presence gate; it does not imply an algorithm
allow-list. Policy and signing-option structs are constructed with builders
rather than public fields so new policy controls can be added without breaking
downstream callers.

Every native Sign1 key resolver receives `(expected_algorithm, protected_kid)`.
Resolvers must use that tuple as the key-store lookup identity and return only
a public key registered for both values; resolving by `kid` alone discards the
algorithm-binding guarantee. The protobuf lane expresses the same restriction
through its algorithm allow-list and trusted `expected_kid` input.

The protobuf operation lane is capped independently at 2 MiB for request
messages and caller-supplied per-operation COSE/payload limits. Native Rust APIs
may opt into larger local limits directly; protobuf callers cannot raise their
parse policy beyond the message envelope cap.

## 0.2.0 Platform Scope

The `0.2.0` release is intentionally Rust and protobuf only. Its publishable
artifacts are `reallyme-cose-proto` and `reallyme-cose`; the `native` and `wasm`
features are Rust runtime lanes, not platform SDK packages.

The `0.2.0` distribution does not include Swift, Android/Kotlin, Kotlin/JVM,
native C/JNI, or TypeScript/WASM npm packages. Those package formats are not
part of this release's compatibility or support contract.

The protobuf `swift_prefix` option is generation metadata, not a published
Swift package. Likewise, `wasm32-unknown-unknown` is a Rust compilation target,
not an npm package. The exact artifact scope is recorded in
[`docs/platform-scope-0.2.0.json`](docs/platform-scope-0.2.0.json).

## Development Checks

Run the full release gate before publishing:

```sh
cargo fmt --check
cargo check --workspace --all-features
RUSTFLAGS=-Dwarnings cargo check --workspace --all-features
RUSTFLAGS=-Dwarnings cargo check --workspace --no-default-features
RUSTFLAGS=-Dwarnings cargo check --workspace --no-default-features --features native,wire
cargo clippy --workspace --all-targets --all-features -- -D warnings
buf lint
buf generate
cargo fmt --package reallyme-cose-proto --check
cargo fmt --manifest-path tools/vector-audit/Cargo.toml --check
cargo clippy --manifest-path tools/vector-audit/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path tools/vector-goldens/Cargo.toml --check
cargo clippy --manifest-path tools/vector-goldens/Cargo.toml --all-targets -- -D warnings
cargo test --workspace --all-features
cargo bench --bench operation_performance --all-features
cargo run --manifest-path tools/vector-audit/Cargo.toml --bin reallyme-cose-vector-audit -- .
cargo nextest run --workspace --no-default-features --features native
cargo check --workspace --no-default-features --features native
cargo check-wasm
cargo deny check
cargo audit
node --test scripts/release-readiness/operation-contract-routing.test.mjs
node scripts/check_release_readiness.mjs
```

Release readiness requires crates.io dependencies for the published ReallyMe
foundational crates: `reallyme-crypto` `^0.3.0` and `reallyme-codec` `^0.2.0`.
Local `../crypto` or `../codec` path dependencies are not accepted for release.

Release readiness structurally inspects all 15 executable operation routes.
After masking Rust comments and literals, it requires one dispatcher branch,
one selected semantic execution, one family result conversion, and one central
failure mapper per route. It also rejects native convenience paths that bypass
the semantic facade and adapters that add direct error classification,
transport codecs, generated result construction, or native convenience facades.
It also caps hand-written Rust modules at 500 lines, rejects substantive inline
test modules, and enforces provider, ownership, concurrency, and performance
controls. The benchmark asserts named peak-allocation ceilings; the host
measurements are recorded in
[`docs/performance-baseline-0.2.0.md`](docs/performance-baseline-0.2.0.md).

The wasm lane must be checked against `wasm32-unknown-unknown`. A host-target
`cargo check --workspace --no-default-features --features wasm` is intentionally
not the supported command because `reallyme-crypto` exposes its wasm provider
exports only when compiling for `wasm32`. Use `cargo check-wasm`, or run the
equivalent explicit command:

```sh
cargo check --workspace --target wasm32-unknown-unknown --no-default-features --features wasm
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Copyright and Trademarks

Copyright © 2026 by ReallyMe LLC.

ReallyMe® is a registered trademark of ReallyMe LLC.
