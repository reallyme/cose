# reallyme-cose-proto

Generated protobuf boundary types for the ReallyMe COSE wire contract.

This crate defines the authoritative public operation contract. Most consumers
depend on `reallyme-cose` for implementation and use its `api::contract`
re-export of these generated types. Service and generated adapter code may
depend on this contract crate directly without a cryptographic runtime.

This crate defines messages only; it intentionally declares no protobuf service.
`CoseOperationRequest` is the single executable adapter request.
`CoseOperationResponseV2` is the typed and binary response: its outcome oneof
contains either `CoseError` or `CoseOperationResult`, whose oneof preserves the
exact identity of all 34 operations. JSON is a generated ProtoJSON request
convenience; encoded executable responses remain binary protobuf messages.

Algorithm selectors are family-scoped. Signature, key-agreement, KEM, and
content-encryption values use the same numeric bands as the corresponding
`reallyme-crypto-proto` families; these protobuf values are not IANA COSE
algorithm identifiers. Operation-specific messages use the narrow family enum.
Only COSE_Key conversion uses `CoseAlgorithmIdentifier`, whose oneof can carry
more than one algorithm family. Earlier compact enum values are reserved so an
old request cannot be silently reinterpreted as a different algorithm.

`CoseSignatureAlgorithm` is the single signature identity selector. Its positive
protobuf numbers remain stable contract IDs; the schema declares the exact
signed IANA wire IDs separately and generates the native mappings from them.
Original ES256/ES384/ES512/EdDSA stay distinct from
ESP256/ESP384/ESP512/Ed25519. `CoseSignatureSuite` resolves the registration and
named key curve together. Curves and MAC selectors retain their explicitly
documented registered numbers. Reader/device role selection, trust policy and
crypto-provider implementation remain external responsibilities.

`CoseProviderCapability` identifies an authorized `(handle, kind)` pair from an
explicit bounded `CoseProviderRegistry`. `CoseProviderCallRequest` and its paired
result/response define descriptions, message/prehash signing, verification,
key/certificate resolution, point validation/normalization and MAC verification.
These are callback messages, not a network service or a secret-key export.
`CoseSigningInput` and `CoseType` use oneofs for mutually exclusive alternatives.

`CoseErrorReason` is the only failure identity list. Mac0 and container adapters
reuse common parsing, key, algorithm, provider and backend reasons, retaining
only family-specific failures. Provider/backend reasons stay in their 200/300
bands. Compatibility Rust names alias the generated reasons without translation.

Version 0.3.0 removes manual `has_*` presence flags. Optional bytes distinguish
absence from an explicitly empty value; enum zero values represent absence.
See the [presence migration](https://github.com/reallyme/cose/blob/main/docs/protobuf-presence-migration.md)
for reserved fields, ProtoJSON behavior and deliberate compatibility changes.

Every public operation is represented: Sign1, ISO and certificate-bearing
containers, opaque signing capabilities, detached Mac0, public agreement and
peer keys, generic key/Multikey operations, ML-KEM encryption, signature
representation conversion, suite inspection and bounded CBOR preflight.
Borrowed Rust and callback APIs adapt these same semantic operations.

The source of truth is `proto/reallyme/cose/v1/cose.proto` inside this crate.
Use Buf 1.73.0 and the published `protoc-gen-reallyme-buffa` /
`protoc-gen-reallyme-buffa-packaging` 0.1.2 executables. From the repository root:

```sh
node scripts/generate_cose_contract.mjs
node scripts/run_pinned_release_readiness.mjs --generated-freshness
```

The complete message family uses native cleanup, guarded repeated storage,
strict JSON fields and local `SecretBytes`/`SecretString` policies. These local
representations own and wipe their allocations, including spare capacity.
Bounded binary hooks reserve the final guarded allocation before reading a
fragmented field; invalid UTF-8 remains guarded too. JSON base64 decoding and
serialization use preallocated wipe-owned scratch, and transferred owned JSON
strings wipe on success and failure.

Generated messages and oneofs implement `Zeroize`, `ZeroizeOnDrop` and `Drop`,
including numeric, nested and error values. Clones own independent protected
copies. `PartialEq` compares message data and is not a cryptographic verifier.
Optional bytes are `Option<SecretBytes>`; builders accept ordinary vectors
through `Into`, and consumers can explicitly transfer a field into a
`Zeroizing<Vec<u8>>`. Repeated fields use `buffa::sensitive::List`.

Unknown wire storage is disabled. Every transport admission must reject unknowns
on the original bounded bytes with `DecodeOptions::reject_unknown_fields()`.
A default decoder may discard them, after which typed validation cannot recover
them. Owned and eager decoding validate the complete message tree. Lazy views,
reflection and imported WKTs are not enabled here; introducing them requires
separate guarded integration and tests.

Owned-message ProtoJSON remains available through native field policies.
Eager/owned-view JSON export is prohibited even for empty values. Views borrow
caller-owned input; their backing bytes, parser input, DOM storage and serialized
output retain independent lifetimes. Keep sensitive transport buffers under
explicit wipe owners.

The [migration matrix](../../docs/buffa-migration.md) accounts for removed
workarounds and retained boundaries. Buffa generates native cleanup and fixed
standalone enum diagnostics directly.

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at
your option (`MIT OR Apache-2.0`). Both license texts are included in
[LICENSE](LICENSE); see [NOTICE](NOTICE) for attribution.
