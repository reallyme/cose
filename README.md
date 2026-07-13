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

## Standards Profile

This crate implements a focused COSE profile over:

- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html), for COSE structures,
  protected and unprotected header maps, COSE_Sign1, Sig_structure construction,
  COSE_Key structure, key identifiers, and CBOR encoding restrictions.
- [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html), for initial COSE
  algorithm identifiers, key types, curve identifiers, and key-parameter labels.

`reallyme-cose` handles COSE_Key construction and parsing, supported
alg/kty/crv mapping, key identifier policy, deterministic CBOR boundary checks,
and the structural COSE_Sign1 parsing needed by mdoc, attestation, credential,
and wallet code. Signing, verification, hashing, and key generation remain in
`reallyme-crypto`.

## Quick Start

```rust
use reallyme_cose::{cose_sign1, cose_verify1_with_policy, Algorithm, CoseError, CosePolicy};
use reallyme_crypto::dispatch::generate_keypair;

fn sign_and_verify() -> Result<(), CoseError> {
    let (public_key, private_key) = generate_keypair(Algorithm::Ed25519)?;
    let kid = b"example-key";

    let cose_bytes = cose_sign1(Algorithm::Ed25519, b"payload", &private_key, Some(kid))?;
    let policy = CosePolicy {
        require_kid: true,
        allowed_algs: vec![Algorithm::Ed25519],
        ..Default::default()
    };

    let verified = cose_verify1_with_policy(&cose_bytes, &policy, |requested_kid| {
        (requested_kid == kid).then(|| public_key.clone())
    })?;
    assert_eq!(verified.payload, b"payload");
    assert_eq!(verified.alg, Algorithm::Ed25519);
    assert_eq!(verified.kid, kid);
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
    CoseSign1EncodeOptions {
        tag: true,
        max_cose_sign1_bytes: 512 * 1024,
    },
)?;
```

Policy-aware verification keeps common platform requirements at the byte API
boundary. `cose_verify1_with_policy` and `cose_verify1_detached_with_policy`
can require `kid`, restrict accepted algorithms, raise or lower byte limits,
and return verified metadata:

```rust
use reallyme_cose::{cose_verify1_with_policy, Algorithm, CosePolicy};

let policy = CosePolicy {
    require_kid: true,
    allowed_algs: vec![Algorithm::P256],
    max_cose_sign1_bytes: 512 * 1024,
    ..Default::default()
};

let verified = cose_verify1_with_policy(&cose, &policy, |kid| resolve_public_key(kid))?;
assert_eq!(verified.alg, Algorithm::P256);
```

## Supported Features

- COSE_Sign1 with attached payloads.
- COSE_Sign1 with detached payloads.
- COSE_Sign1 signing can emit either untagged messages or messages carrying the
  registered COSE_Sign1 root tag (18) through `cose_sign1_tagged`,
  `cose_sign1_detached_tagged`, or `CoseSign1EncodeOptions`.
- Ed25519, P-256, P-384, P-521, and secp256k1 signing.
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
- Private COSE_Key extraction returns a zeroizing buffer. Because
  `coset::CoseKey` stores private parameters in ordinary CBOR value buffers,
  keep private COSE_Key values short-lived and extract them only at backend
  boundaries.
- COSE_Key public conversion for X25519 key-agreement keys.
- COSE_Key to Multikey and Multikey to COSE_Key conversion.
- `kid = SHA-256(canonical public-only COSE_Key)` derivation.
- Portable vectors in `conformance/vectors/cose-sign1.json` and
  `conformance/vectors/cose-key.json`. ECDSA vectors are the cross-lane
  contract for fixed-width `r || s` signatures; Swift, Kotlin, TypeScript, and
  other SDK lanes must reject DER signatures at the COSE boundary.

## Independent Vector Audit

`tools/vector-audit` is a standalone, unpublished Cargo binary that audits the
committed vector JSON with RustCrypto, `ciborium`, and `bs58`. It does not
depend on `reallyme-cose`, `reallyme-crypto`, or `reallyme-codec`, which keeps
the vector checks independent from the implementation under test.

## Unsupported COSE Surface

The following structures and features are not implemented:

- COSE_Mac0, COSE_Mac, and MAC verification.
- COSE_Encrypt0, COSE_Encrypt, and recipient processing.
- COSE_Sign multi-signer structures.
- Countersignatures.
- Critical protected headers.
- Integrity-sensitive fields in unprotected headers, including `alg` and `kid`.
- Indefinite-length CBOR at public byte boundaries.
- Unexpected CBOR tags except a root COSE_Sign1 tag when decoding Sign1 input.
- Algorithms outside the explicit mapping above.

Unsupported inputs fail closed with typed `CoseError` variants. Error messages
do not include payloads, keys, raw CBOR, or resolver-provided material.

## Resource Limits

Public byte-boundary APIs enforce deterministic limits before COSE structure
decoding:

- COSE_Sign1 input: 65,536 bytes.
- COSE_Key input: 16,384 bytes.
- Detached payload input: 1,048,576 bytes.

The default attached COSE_Sign1 limit is 65,536 bytes. Consumers that need
larger attached reports can opt into a higher limit with
`CoseSign1EncodeOptions::max_cose_sign1_bytes` when signing and
`CosePolicy::max_cose_sign1_bytes` when verifying. Large application payloads
should still prefer detached signing and enforce transport or application-level
limits before calling this crate.

## Development Checks

Run the full release gate before publishing:

```sh
cargo fmt --check
cargo check --workspace --all-features
RUSTFLAGS=-Dwarnings cargo check --workspace --all-features
RUSTFLAGS=-Dwarnings cargo check --workspace --no-default-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --manifest-path tools/vector-audit/Cargo.toml --check
cargo clippy --manifest-path tools/vector-audit/Cargo.toml --all-targets -- -D warnings
cargo test --workspace --all-features
cargo run --manifest-path tools/vector-audit/Cargo.toml -- .
cargo nextest run --workspace --no-default-features --features native
cargo check --workspace --no-default-features --features native
cargo check --workspace --target wasm32-unknown-unknown --no-default-features --features wasm
cargo deny check
cargo audit
node scripts/check_release_readiness.mjs
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Copyright and Trademarks

Copyright © 2026 by ReallyMe LLC.

ReallyMe® is a registered trademark of ReallyMe LLC.
