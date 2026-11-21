# reallyme-cose-proto

Protobuf messages and codecs for ReallyMe COSE. Use `reallyme-cose` to execute
operations; depend on this crate directly to exchange requests, results and
provider callbacks without a cryptographic runtime.

The schema is `proto/reallyme/cose/v1/cose.proto`. It defines no network service.
`CoseOperationRequest` selects an operation. `CoseOperationResponseV2` contains
either a `CoseOperationResult` for that operation or a typed `CoseError`.
Executable requests support binary protobuf and ProtoJSON; encoded responses
use binary protobuf.

Signature algorithms use stable protobuf selectors, separate from signed IANA
COSE identifiers. `CoseSignatureSuite` pairs an exact registration with a named
curve. ES256/ES384/ES512/EdDSA and ESP256/ESP384/ESP512/Ed25519 remain distinct.
Do not infer authorization from a curve or public-key encoding.

Provider callbacks use `CoseProviderCallRequest` and its response types.
`CoseProviderRegistry` authorizes operation-local `(handle, kind)` capabilities;
handles do not serialize a provider or establish trust.

In 0.3.0, optional bytes distinguish absent and present-empty values. Retired
`has_*` flags are rejected. See the
[presence migration](https://github.com/reallyme/cose/blob/main/docs/protobuf-presence-migration.md).

Messages own sensitive fields through `SecretBytes`, `SecretString` and guarded
collections, with redacted formatting and zeroization on drop. Clones own
separate copies. Callers must protect and erase source buffers, JSON parser
storage and serialized output. Generated equality is a data comparison, not
a constant-time cryptographic check.

For untrusted binary input, apply bounded decoding with
`DecodeOptions::reject_unknown_fields()` to the original bytes. The default
decoder can discard unknown fields. Prefer ReallyMe COSE's executable adapters,
which enforce transport and operation limits. View JSON export is disabled.

See the [operation API](https://github.com/reallyme/cose/blob/main/docs/generated-operation-contract.md)
for execution and provider integration, and
[generation instructions](https://github.com/reallyme/cose/blob/main/docs/buffa-migration.md)
for tool versions and dependency constraints.

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at
your option (`MIT OR Apache-2.0`). See [LICENSE](LICENSE) and [NOTICE](NOTICE).
