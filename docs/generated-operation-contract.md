# Protobuf operation API

`crates/proto/proto/reallyme/cose/v1/cose.proto` defines requests, results,
policies, algorithm selectors and `CoseErrorReason`. Rust exposes these types
through `reallyme_cose::api::contract`.

| Input | Entry point | Output |
| --- | --- | --- |
| Generated request | `api::execute` | `CoseOperationResponseV2` |
| Generated request with native providers | `api::execute_with_providers` | `CoseOperationResponseV2` |
| Generated request with schema-defined callbacks | `api::execute_with_provider_transport` | `CoseOperationResponseV2` |
| Binary protobuf | `wire::execute_operation_proto` | Zeroizing binary response |
| ProtoJSON | `wire::execute_operation_proto_json` | Zeroizing binary response |

For encoded requests with native providers, use
`api::execute_protobuf_with_providers` or `api::execute_json_with_providers`.
A response contains either the matching operation result or a fixed error
reason. No result is authenticated when the outcome is an error.

Binary requests are limited to 2 MiB and JSON requests to 3 MiB. Executable
adapters reject unknown fields; the JSON boundary also rejects escaped strings.
Operation-specific size, nesting and collection limits still apply.
`CoseByteLimits` distinguishes an omitted limit from an explicit zero. Legacy
zero-valued scalar limits select their documented defaults.

Sign1 defaults to 65,536 encoded bytes. An explicit encoded budget can select
up to 1,048,576 bytes for signing, decoding and verification. Larger selections
return `COMMON_RESOURCE_LIMIT_EXCEEDED`. Payload, AAD, certificate and structural
limits are independent.

## Keys and providers

Choose exact `CoseSignatureAlgorithm` registrations and `CoseSignatureSuite`
curves. Protobuf selector numbers are not COSE wire identifiers. Direct Sign1
verification requires `public_key_algorithm`; resolve that value from trusted
key metadata. See [Sign1 key binding](sign1-key-binding.md).

Implement `ProviderTransport` to exchange generated callback messages, or
`OperationProviders` for native callbacks. Supply a bounded
`CoseProviderRegistry` of authorized nonzero `(handle, kind)` pairs. Provider
replies must match the requested result, suite, key and verification context.
Missing capabilities return a typed error. Container signing also requires
verification of the provider's output.

Certificate providers must return the selected leaf DER with the working key.
COSE binds it to the received chain and protected registration. Certificate-path
trust and application authorization remain the provider's responsibility.
See [signed containers](signed-container-contracts.md).

Protected headers, payloads and original COSE_Key encodings are byte fields;
normalized public points are separate. Never rebuild authenticated bytes or
transcripts from decoded fields. Message owners wipe their fields on drop;
callers own the lifetime and erasure of input, parser and serialized copies.

For operation-specific contracts, see [message families](message-family-support.md),
[agreement keys](agreement-keys.md), [ISO Sign1](iso18013-signature-profile.md)
and [presence migration](protobuf-presence-migration.md).
