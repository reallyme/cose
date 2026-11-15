# ReallyMe Buffa integration

The runtime and both local generators use published ReallyMe Buffa 0.1.2.
The generator supplies native cleanup and fixed standalone enum diagnostics
without source transformations. Rust uses the `buffa` dependency alias.
COSE package versions, Rust 1.100 MSRV, protobuf package names and field
numbers are preserved.

## Security equivalence matrix

| Previous workaround | Native configuration or retained boundary | Regression evidence |
| --- | --- | --- |
| Generated Drop/clear/scalar/oneof patches | `zeroize_in=.reallyme.cose.v1`, `buffa/zeroize`; complete message family, native guarded lists | Lifecycle, replacement, numeric and partial-failure tests |
| Generated redacted Debug for fields/views | Cleanup profile redacts complete messages and oneof selection | Owned, eager and owned-view Debug tests |
| Handwritten generated JSON visitors | Native cleanup visitors, `deny_unknown_json_fields=true`, explicit local byte/string JSON policies | Presence, duplicate/unknown JSON, late-failure and allocator tests |
| Fixed standalone enum JSON diagnostics | Native closed-enum JSON helper omits rejected names and numbers from diagnostics | `generated_proto_json_enum_errors_do_not_reflect_untrusted_values` |
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

## Generated diagnostics and compatibility projections

The fixed diagnostics cover unknown enum names, unknown integers and integers
outside the i32 range. Generated message fields retain their open
`EnumValue` behavior. The executable boundary validates the values allowed
by each operation.

The remaining separate generator emits native borrowed adapters, reason aliases
and equality compatibility. A local-plugin `type_attribute` option could replace
the `Eq` companion generation. Removing the other projections would require a
schema-native representation of the Rust lifetime adapters and compatibility
aliases. Version, freshness and reachability checks remain repository policy.
