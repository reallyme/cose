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
Use Buf 1.72.0 and `protoc-gen-buffa` / `protoc-gen-buffa-packaging` 0.9.2.
From the repository root, regenerate after changing the schema or hardening pass:

```sh
buf lint
buf generate
node scripts/harden-generated-cose-proto.mjs
cargo fmt --package reallyme-cose-proto
node scripts/check_release_readiness.mjs --generated-freshness
```

The hardening pass redacts byte-valued request/result fields from `Debug` and
adds zeroization to generated `clear`, JSON partial-deserialization owners, and
message drop paths. Repeated binary byte and string fields wipe the previous
value before replacement and release excess retained capacity to bound wiping
work across repeated small fields. Contiguous strings are validated before
copying; fragmented string bytes remain under a zeroizing owner during UTF-8
validation. Sensitive messages also recursively wipe length-delimited unknown
protobuf fields on `clear` and drop. Buffa requires generated messages
to implement `Clone`; each clone is therefore an additional transient byte
owner and is wiped on drop. Generated `PartialEq` is not a constant-time secret
comparison primitive. ProtoJSON serialization returns a caller-owned `String`
that this crate cannot wipe, so callers must retain sensitive JSON in a
zeroizing owner and release it promptly after transport. Managed-language
protobuf generators cannot promise equivalent memory erasure, so SDK wrappers
must document best-effort buffer clearing separately.

This crate's generated Buffa mapping is the only JSON contract for the COSE
wire messages. `buf.gen.yaml` enables ProtoJSON and borrowed Rust views;
the hardening pass enforces strict unknown-field rejection and redacts sensitive
byte fields from borrowed-view `Debug`. Borrowed views reference caller-owned protobuf bytes and cannot erase
that memory, so only owned generated messages claim wipe-on-drop behavior.

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at
your option (`MIT OR Apache-2.0`). Both license texts are included in
[LICENSE](LICENSE); see [NOTICE](NOTICE) for attribution.
