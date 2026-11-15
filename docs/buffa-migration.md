# ReallyMe Buffa integration

Release blocker: published 0.1.0 still requires a standalone-enum diagnostic
source transformation. Native cleanup is integrated, but the complete migration
requires a published generator fix that preserves fixed diagnostics without
patching its output. The narrow guard remains solely to preserve the existing
security contract while that dependency requirement is unresolved.

The runtime and both local generators use the published ReallyMe Buffa 0.1.0
family. Rust retains the `buffa` dependency alias. COSE package versions, Rust
1.100 MSRV, protobuf package names, field numbers and cryptographic vectors
remain unchanged. No service, descriptor, reflection, WKT or build-script
integration is present in this repository. The crypto/codec operation-contract
features are not enabled; their optional upstream runtime is not interchangeable
with the COSE runtime.

## Security equivalence matrix

| Previous workaround | Native configuration or retained boundary | Regression evidence |
| --- | --- | --- |
| Generated Drop/clear/scalar/oneof patches | `zeroize_in=.reallyme.cose.v1`, `buffa/zeroize`; complete message family, native guarded lists | Lifecycle, replacement, numeric and partial-failure tests |
| Generated redacted Debug for fields/views | Cleanup profile redacts complete messages and oneof selection | Owned, eager and owned-view Debug tests |
| Handwritten generated JSON visitors | Native cleanup visitors, `deny_unknown_json_fields=true`, explicit local byte/string JSON policies | Presence, duplicate/unknown JSON, late-failure and allocator tests |
| Fixed standalone enum JSON diagnostics | Published generator gap: retain the narrow `sanitize_enum_diagnostics.mjs` guard; it changes only the two numeric diagnostics in standalone enum serde implementations | `generated_proto_json_enum_range_errors_do_not_reflect_untrusted_values`; guard mutation tests |
| Patched byte/string merge functions | Local wipe-owning `SecretBytes`/`SecretString`, bounded `decode_length_delimited` hooks | Fragmented input, invalid UTF-8, duplicate replacement and failed decode |
| Ordinary repeated byte/message/enum buffers | Native `buffa::sensitive::List`, including numeric slots and outgrown allocations | Growth, clone and clear/drop observations |
| Retained unknown-field cleanup and recursive typed checks | `unknown_fields=false`; explicit zero-allowance wire admission; unknown data cannot inhabit a typed message | Nested/group/unknown wire rejection and complete-tree admission |
| Ordinary JSON base64 scratch | Local `ProtoBytesJson` reserves guarded storage before decoding; wipes encoded owned strings and serialization scratch | Owned JSON, malformed base64, optional/repeated fields and allocation tests |
| View export policy | `deny_view_json=.reallyme.cose.v1`, including empty and containing views | Whole-view export rejection, owned JSON compatibility |
| Schema-derived native projections and reason aliases | Retained separate contract generation; no Buffa output rewriting | Operation/type reachability and regeneration tests |
| Canonical protobuf and domain validation | Retained bounded codecs, re-encoding checks, typed errors and provider authorization | Existing native/protobuf/JSON parity and independent vectors |
| Transport, parser and borrowed input ownership | Retained source owners and JSON escape rejection; serialized copies remain caller-owned | Existing size/recursion/encoding/ownership tests |

Every cloned secret field owns and wipes its own allocation. Owned view backing
bytes and explicitly serialized protobuf/JSON buffers remain separate ownership
boundaries. Native cleanup does not erase caller copies or JSON parser scratch.

No lazy view, map, reflection or imported WKT tree is generated here. Adding an imported tree requires the
guarded imported family, feature and inspection configuration before admission;
ordinary WKTs and dynamic reflection snapshots do not satisfy cleanup policy.

## Generator follow-up

In ReallyMe Buffa tag `reallyme-v0.1.0`, `generate_enum_serde` in
`buffa-codegen/src/enumeration.rs` interpolates numeric input into both error
branches of the generated `visit_i64` and `visit_u64` methods. The native guarded
field policies cover enum fields in cleanup messages, but do not replace
standalone concrete-enum `Deserialize` implementations.

Generate a proto3 enum with values 0 and 1 using the published local plugins and
`json=true`, then call `serde_json::from_str::<Algorithm>` on `42424242`,
`-42424242`, `-9223372036854775808` and `18446744073709551615`. Unknown values
must return the fixed `unknown enum value` diagnostic; values outside i32 must
return `enum value out of i32 range`. Neither should reflect the input token.
The failure reproduces with the unmodified published output, including with
`zeroize_in` and `deny_unknown_json_fields` configured. Preserve valid enum names
and numeric values, and preserve open `EnumValue` field behavior.
The four invalid cases fail against the published generator; valid symbolic
and numeric values continue to decode.

After a matching fixed runtime/generator family is published, update exact pins,
remove the diagnostic guard and regenerate. The existing regression test must
pass against unmodified generator output. Crate preflight and publication reject the guarded migration. Development CI
still verifies the existing guarded bindings and their regression tests.

The remaining separate generator emits native borrowed adapters, reason aliases
and equality compatibility. A local-plugin `type_attribute` option could replace
the `Eq` companion generation. Removing the other projections would require a
schema-native representation of the Rust lifetime adapters and compatibility
aliases. Version, freshness and reachability checks remain repository policy.
