# Generated COSE operation contract

The protobuf schema is authoritative for every public operation in 0.3.0.
ReallyMe Buffa 0.1.2 generates request/result types, policy selectors, operation variants,
binary/JSON codecs and stable failure codes. The implementation stays behind
that contract. Existing borrowed Rust and callback signatures are retained as
thin adapters to the same semantic functions; they do not serialize and decode
authenticated bytes to cross the boundary.

`api::contract` exposes the generated definitions. `api::execute` accepts
`CoseOperationRequest` and returns `CoseOperationResponseV2` directly.
`api::execute_with_providers` adds caller-owned capabilities. For encoded input,
use `wire::execute_operation_proto` / `execute_operation_proto_json`, or the
corresponding provider-aware methods in `api`. Both `native` and `wasm` include
the generated operation contract. No service or platform SDK is introduced.

All 34 operation/result identifiers are paired: 33 cryptographic/format
operations and a generated constant-catalog operation. Independent COSE vector bytes and retained protobuf field numbers are preserved.
The [0.3.0 presence migration](protobuf-presence-migration.md) deliberately retires
manual flags and adds explicit byte presence. Native selectors,
policy builders and error names now derive from the schema; 0.3.0 is the
compatibility boundary for these consolidated value types. Borrowed readers
and callbacks continue to share the semantic implementation.

The separate contract driver also generates 17 native request/result projections and five
borrowed content/callback enums from schema metadata. Field types and byte
presence come from the Buffa message definitions. Every source field is either
projected or explicitly supplied by a separate capability or argument; adding a
field or oneof case without accounting for it fails generation. Receipt byte
owners use `Zeroizing`, including the legacy certificate-path result. Its
`x5chain_der` field now exposes a `Zeroizing<Vec<Vec<u8>>>`; callers can borrow
the path through `as_slice()` without copying it.

Handwritten public structs are limited to generated-message builders, borrowed
provider selections and process-local key/capability owners. They do not define
another request or result model. Release checks reject handwritten DTO shapes,
parallel policy fields and unbound functions in transport and nested modules.

Agreement construction/import now share allowlist validation across native and
generated entrypoints: nonempty, unique agreement curves, with at most nine
entries. Empty native curve policies return the same resource-limit reason as
protobuf requests. Signature-suite and MAC allowlists share the schema-defined
32-entry bound. Every supplied signature tuple is checked, including unused
entries; malformed policies cannot depend on which entrypoint receives them.

Signature-purpose peer inspection under `ValidateCose` also accepts an optional
byte-string Base IV (label 5). The exact key encoding retains that parameter,
while public material and signature inputs exclude it. Algorithm and key-operation
checks remain active. Shape inspection and mathematical point validation remain
distinct operations. Native, protobuf and ProtoJSON regression tests cover
identical keys with and without Base IV, malformed values, duplicate parameters,
public-only material and resource limits; native allocator observation verifies
wiping on owner drop and failed point validation.

## Type-contract audit matrix

| Audit requirement | Authoritative contract / implementation | Evidence |
| --- | --- | --- |
| One signature identity and suite | Positive `CoseSignatureAlgorithm` selectors, exact signed wire-ID metadata, one `CoseSignatureSuite`; generated native closed views and ISO aliases | Twelve independent wire registrations; original/modern identity, hash/curve and mismatch tests; published algorithm selector numbers remain frozen |
| Native presence | Nine optional byte fields, enum zero for absent algorithms; 11 flags reserved | Absent/empty/nonempty byte and JSON vectors; real KDF authentication and ISO receipt presence tests |
| One policy allowlist | `CoseVerificationPolicy.allowed_algorithms`; native `CosePolicy` owns that generated message | Explicit empty denial, exact-registration roundtrip; old crypto selector builders expand immediately into the same list |
| One error identity list | Generated `CoseErrorReason`; a fixed `thiserror` owner with compatibility aliases; no second native reason enum | Every reason maps through its proper branch; shared CBOR/key/algorithm/provider/backend reasons; retired unpublished duplicate IDs reserved |
| Single selectors, encodings and limits | Generated curves, point/signature encodings, content/key-source selectors and `CoseByteLimits`; generated closed or borrowed views | All closed-selector total conversions reject zero/unknown; exact key bytes separate from normalized points; explicit-zero and cross-lane limits |
| Complete callback/provider contract | `CoseProviderRegistry`, typed capabilities, descriptions, `CoseSigningInput` oneof and paired callback request/result/response | Schema-only provider tests roundtrip binary messages; independent EdDSA/ECDSA, MAC, certificates, ISO verifier and point normalization; wrong mode/role/result/unknown/bounds tests |
| Remaining public values | Generated ML-KEM profile, constants and `contract_info` (5001); generated `CoseType` oneof | Constant-catalog tampering rejected; mutually exclusive media type/content format; generated-owner/drop tests |
| Reachability and drift prevention | Schema field projections, adapter, port, owner and value-method declarations; release operation/type guards | Negative guard tests reject missing/duplicate fields, new oneof arms, a second owned DTO or policy field, and unbound free/associated/nested/transport functions |

The frozen v1 `CoseEc2PointEncoding` selector remains only for published-message
compatibility. Its single generated conversion maps to canonical
`CosePointEncoding`; new operations use the canonical selector. Legacy positive
signature primitive selectors likewise convert at the generated compatibility
boundary. Neither changes a received COSE registration or selects a profile.
Closed suite projection validates selectors; each entrypoint then validates its
profile and algorithm/curve tuple. Recognition cannot authorize an ISO/modern
profile substitution. Native `SigningMode` is generated from the schema's mode
and hash relationship;
`SigningInput` borrows the corresponding message/prehash oneof. Borrowed slices
and capability references retain Rust lifetimes instead of becoming a second
owned data model.

## Operation and adapter matrix

The complete schema is
`crates/proto/proto/reallyme/cose/v1/cose.proto`. Its `Rust adapter` declarations
bind retained Rust signatures to their operation. Release readiness rejects an
unrepresented public operation, duplicate dispatch, missing result pairing or
a substantive implementation in a compatibility facade.

| Operations / field numbers | Generated request/result | Shared semantics / retained adapters |
| --- | --- | --- |
| `sign1_create`, `sign1_create_detached` 1000–1001 | Existing Sign1 creation requests/results | Attached/detached creation and exact-registration selection |
| `sign1_verify`, `sign1_verify_detached` 1002–1003 | Existing Sign1 verification requests/results | Explicit public-key, kid, algorithm, AAD, tag and typ validation |
| `iso_sign1_verify` 1004 | `CoseIsoSign1VerifyRequest` / `Result` | Original ES256/ES384/ES512/EdDSA with explicit named-curve tuples; attached issuer and detached device/reader content; empty AAD |
| `container_verify` 1005 | `CoseContainerVerifyRequest` / `Result` | Certificate-header/x5t binding, exact bytes, selected working key/context and provenance for explicit 2021, DIS and RFC 9360 profiles |
| `container_sign` 1006 | `CoseContainerSignRequest` / `CoseOpaqueBytes` | Finalized exact headers/content; non-exporting signer; independent output verification; message/prehash modes remain bound to the capability |
| `signature_to_cose`, `signature_to_der`, `signature_validate` 1010–1012 | `CoseSignatureConvertRequest`; opaque bytes or `CoseValidationResult` | Strict declared DER/fixed-width/EdDSA conversion and scalar/length checks |
| `signature_suite_info` 1013 | `CoseSuiteInfoRequest` / `Result` | Separate ISO family compatibility and ISO table-pair validation; named widths and built-in provider availability |
| `sign1_create_profile`, `sign1_create_detached_profile` 1014–1015 | `CoseSign1CreateProfileRequest` / `CoseSign1CreateResult` | All modern creation options, protected typ and raw/non-exporting key sources |
| `sign1_verify_profile` 1016 | `CoseSign1VerifyProfileRequest` / `CoseSign1VerifyResult` | Borrowed key-resolution callbacks, attached/detached content and explicit unprotected-chain opt-in |
| `sign1_verify_x5chain` 1017 | `CoseSign1VerifyProfileRequest` / `CoseSign1X5ChainResult` | Exact-registration certificate callback; placement and certificate bytes reported independently of path trust |
| Key construction, parse, extraction, kid and Multikey 2000–2007 | Existing key/Multikey requests/results | Existing generic signing/AKP/KEM profiles, deterministic encoding and algorithm-bound kid derivation |
| `agreement_key_create`, `agreement_key_parse` 2008–2009 | `CoseAgreementKeyCreateRequest`, `ParseRequest` / `Result` | Public-only agreement keys, omitted alg, agreement key_ops, original map bytes separate from normalized points, explicit curve and EC2 encoding policy |
| `peer_key_inspect`, `peer_key_validate` 2010–2011 | `CosePeerKeyRequest` / `Result` | Distinct unvalidated inspection and mathematical validation for signature/agreement/HPKE purposes; all eleven registered mappings |
| `verification_key_import` 2012 | `CoseVerificationKeyImportRequest` / `CoseWorkingKey` | Raw or public-only COSE key import; exact suite and fixed context identity |
| ML-KEM direct, key-wrap and decrypt 3000–3002 | Existing ML-KEM requests/results | Existing content algorithms, KDF context, authenticated recipient kid and protected ownership |
| `mac0_verify_detached` 4000 | `CoseMac0VerifyRequest` / `Result` | Exact protected bytes, explicit payload/AAD/allowlist, protected direct key or local handle; metadata excludes payload and key |
| `contract_info` 5001 | `CoseContractInfoRequest` / `Result` | Generated public algorithm/header/limit constants; exact catalog validation |
| `preferred_cbor_validate` 5000 | `CoseOpaqueBytes` / `CoseValidationResult` | Bounded preferred CBOR, unique unsorted maps and complete consumption; no ISO message-schema verdict |

Value-owner getters and policy builders are compatibility views of these
generated selectors/results, not separate cryptographic operations. Public
key, verifier and suite construction are represented by key import, peer
validation and suite-info operations. Protected key owners and injected ports
remain process-local capabilities rather than serialized secret containers.

## Capabilities, bytes and failures

`api::execute_with_provider_transport` invokes the complete generated callback
contract through `ProviderTransport`. A bounded registry authorizes nonzero
`(handle, kind)` pairs. Old `OperationProviders` callbacks are process-local
adapters to the same operations. Every provider reply is untrusted: the adapter
checks recursive unknown fields, result identity, fixed error branch, sizes,
encoding and key/suite/context binding before use. It supports protected MAC
keys, modern/ISO verification callbacks, validated working keys, external certificate validation, signers and
named-point validation/normalization. Missing capabilities fail closed. No
global handle registry, private-key export or provider fallback is created.
Container signing independently verifies the result using the built-in crypto
verifier or a separately authorized verification capability. An external
verifier must match the signer's exact suite, public bytes and context. Modern
Sign1 signing uses built-in crypto verification and rejects an extra verifier
capability. Trust policy remains in the injected certificate boundary. Received
discovery headers do not authorize the selected working key or grant path trust.

Opaque byte fields preserve exact received protected/unprotected maps, payloads
and COSE_Key encodings. Normalized points occupy separate fields. Caller-owned
tag-24 wrappers and transcript ordering remain external. No request, callback
or normalized point is used to reconstruct authenticated bytes.

All generated message owners implement `ZeroizeOnDrop`, redact Debug, disable
unknown storage, and protect partial
ProtoJSON decoding. Certificate arrays also wipe completed elements when a
later element fails. Capability handles are redacted and cleared on drop.
Borrowed/owned views still refer to caller-owned serialized backing storage.
Generated Clone produces another explicit owning buffer; callers must limit
and clear any serialized copies they create. Generated PartialEq is a data-model
comparison and is never a cryptographic verifier.

Unknown values cannot inhabit typed requests. The strict binary decoder
rejects them on original bytes before storage could discard them. ProtoJSON also rejects unknown fields and escaped-string
inputs at the executable boundary. Encoded protobuf requests remain capped at
2 MiB, JSON at 3 MiB; per-operation byte, collection, depth and work bounds still
apply. New `CoseByteLimits` distinguishes absence (hard defaults) from a present
zero ceiling. Legacy zero-valued limit fields retain their existing defaults.

Failures contain only fixed generated codes. `CoseErrorReason` is the sole list;
`CoseError`, `CoseMac0Error`, `ContainerError` and `CoseSignerError` share the
same allocation-free owner. Common failures keep common codes. Provider errors
occupy 200–299 and backend errors 300–399, without family-range exceptions.
Only detached-content/tag-length and container-profile/certificate/thumbprint/
signing-input reasons remain family-specific. No error contains input buffers,
handles, arbitrary strings or backend exception text.

## Validation and compatibility evidence

The retained tests continue exercising borrowed APIs, callback behavior,
malformed inputs, ownership and independent standards answers. Added contract
tests compare typed, binary and ProtoJSON responses, then compare exact bytes
and metadata with the borrowed/native results. Coverage includes independent
ISO and container fixtures, all eleven key mappings, deterministic non-exporting
EdDSA signing, protected MAC handles, certificate callbacks, tampering, limits,
unknown fields and request/result mismatch handling. Tests execute in native
and WASM/Node; allocation-counter checks remain native-only.

| Requirement / clauses | Contract and evidence |
| --- | --- |
| RFC 9052 6.2–6.3 | Operation 4000, independent COSE Working Group MAC answers, changed payload/AAD/key/tag and fixed native/generated errors |
| ISO 2021 8.1 and 9.1.5.2; DIS 8.3 and 12.7.2 | Operations 2008–2011/5000, exact unsorted unique maps, separate normalized points, caller-selected full/compressed policy, private/duplicate/wrong-purpose failures |
| Original ISO signature registrations | Operations 1004/1013/2012, independent exact-registration/curve cases, no modern-ID substitution; unavailable pairs stay typed failures |
| Certificate headers, SHA-256 x5t, revocation/RICAL and ReaderAuthAll content | Operations 1005–1006 and retained detailed [clause matrix](signed-container-contracts.md); exact bytes and certificate substitution tests |
| Protected ownership and deterministic boundary errors | Native schema-derived cleanup, explicit unknown-field rejection, generated owned/view tests and contract resource/metadata tests |

## Versions and remaining integration

ReallyMe Buffa 0.1.2 supplies native cleanup and fixed standalone enum
diagnostics. See the [migration matrix](buffa-migration.md) for ownership
and diagnostic regression coverage.

| Check | Result |
| --- | --- |
| Debug workspace tests, including doctests | 452 passed |
| Native nextest / optimized all-features nextest | 450 / 450 passed |
| WASM/Node unit / integration tests | 109 / 4 passed |
| Independent legacy conformance vector audit | 55 cases passed |
| Format, warnings-as-errors checks, strict Clippy and external-type checks | Passed |
| Buffa regeneration/freshness and operation/type-contract guards | Passed |
| Rustdoc public export inventory | 65 schema-bound free functions; no handwritten public COSE enums |
| Seven iOS/Android Rust targets | All-target compile checks passed |
| All four lockfiles and dependency/advisory policy | Passed; no known advisories reported |
| Instrumented fuzz build | All targets built |

These are compile, test and bounded smoke results, not a proof of complete fuzz
coverage, on-device execution or reader interoperability. Existing independent
fixture files and their expected cryptographic bytes were retained unchanged.

The workspace packages are `reallyme-cose` 0.3.0 and `reallyme-cose-proto` 0.3.0,
using the published dependencies `reallyme-crypto` 0.4.2 and
`reallyme-codec` 0.4.3. ReallyMe Buffa and both generators are 0.1.2, Buf is 1.73.0,
the stable compiler is Rust 1.100.0, and the minimum Rust version is 1.100.
CI and the local runner use Release Readiness 0.9.5.

Brainpool, Ed448 and X448 provider implementation remains in `reallyme/crypto`.
This repository recognizes registered mappings and fails closed where the
built-in COSE provider adapter lacks coverage. Schema generation is not provider execution
evidence. The suite-info provider flag reports the built-in tuple mapping,
independently of runtime authorization or platform readiness. Reader negotiation,
session establishment, transcript construction,
HPKE, format schemas, certificate authority/path policy and revocation freshness
remain external. iOS/Android validation covers Rust target compilation. Device execution and
SDK packaging are outside this repository's validation scope.
