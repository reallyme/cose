<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-cose-proto

Generated protobuf boundary types for the ReallyMe COSE wire contract.

This crate is a low-level generated contract crate, not the ergonomic COSE SDK.
Most consumers should depend on `reallyme-cose`; service, FFI, and generated
adapter code may use this crate when it needs the protobuf message types
directly.

This crate defines messages only; it intentionally declares no protobuf service.
`CoseOperationRequest` is the single executable adapter request.
`CoseOperationResponseV2` is the binary response: its outcome oneof
contains either `CoseError` or `CoseOperationResult`, whose oneof preserves the
exact identity of all 15 operations. JSON is a generated ProtoJSON request
convenience; executable responses remain binary protobuf messages.

Algorithm selectors are family-scoped. Signature, key-agreement, KEM, and
content-encryption values use the same numeric bands as the corresponding
`reallyme-crypto-proto` families; these protobuf values are not IANA COSE
algorithm identifiers. Operation-specific messages use the narrow family enum.
Only COSE_Key conversion uses `CoseAlgorithmIdentifier`, whose oneof can carry
more than one algorithm family. Earlier compact enum values are reserved so an
old request cannot be silently reinterpreted as a different algorithm.

The source of truth is `proto/reallyme/cose/v1/cose.proto` inside this crate.
Regenerate this crate with `buf generate` from the repository root after
changing the schema, then run `node scripts/harden-generated-cose-proto.mjs`.

The hardening pass redacts byte-valued request/result fields from `Debug` and
adds zeroization to generated `clear`, JSON partial-deserialization owners, and
message drop paths. Sensitive messages also recursively wipe length-delimited
unknown protobuf fields on `clear` and drop. Buffa requires generated messages
to implement `Clone`; each clone is therefore an additional transient byte
owner and is wiped on drop. Generated `PartialEq` is not a constant-time secret
comparison primitive. ProtoJSON serialization returns a caller-owned `String`
that this crate cannot wipe, so callers must retain sensitive JSON in a
zeroizing owner and release it promptly after transport. Managed-language
protobuf generators cannot promise equivalent memory erasure, so SDK wrappers
must document best-effort buffer clearing separately.

This crate's generated Buffa mapping is the only JSON contract for the COSE
wire messages. `buf.gen.yaml` enables strict ProtoJSON and borrowed Rust views;
the hardening pass also redacts sensitive byte fields from borrowed-view
`Debug`. Borrowed views reference caller-owned protobuf bytes and cannot erase
that memory, so only owned generated messages claim wipe-on-drop behavior.
