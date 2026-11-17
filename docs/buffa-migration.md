# ReallyMe Buffa integration

ReallyMe Buffa 0.1.3 generates the wire model and all native enum adapters.
Rust retains the `buffa` dependency alias at runtime version 0.1.2, matching the
exact requirement of Codec 0.4.3. Cargo cannot select runtime 0.1.3 alongside
that requirement. The native adapters use the existing runtime's `EnumValue`
API. Updating the runtime requires a compatible Codec release.

COSE package versions, Rust 1.100 MSRV, protobuf package names, field numbers
and cryptographic vectors remain unchanged. No service, reflection, WKT or
build-script integration is present. The crypto/codec operation-contract
features are not enabled.

## Security equivalence matrix

| Previous workaround | Native configuration or retained boundary | Regression evidence |
| --- | --- | --- |
| Generated Drop/clear/scalar/oneof patches | `zeroize_in=.reallyme.cose.v1`, `buffa/zeroize`; complete message family, native guarded lists | Lifecycle, replacement, numeric and partial-failure tests |
| Generated redacted Debug for fields/views | Cleanup profile redacts complete messages and oneof selection | Owned, eager and owned-view Debug tests |
| Handwritten generated JSON visitors | Native cleanup visitors, `deny_unknown_json_fields=true`, explicit local byte/string JSON policies | Presence, duplicate/unknown JSON, late-failure and allocator tests |
| Fixed standalone enum JSON diagnostics | Buffa generates calls to `closed_enum::deserialize_strict` with input-independent error reasons | `generated_proto_json_enum_errors_do_not_reflect_untrusted_values` and `generated_proto_json_enum_defaults_and_lenient_behavior_are_preserved` |
| Patched byte/string merge functions | Local wipe-owning `SecretBytes`/`SecretString`, bounded `decode_length_delimited` hooks | Fragmented input, invalid UTF-8, duplicate replacement and failed decode |
| Ordinary repeated byte/message/enum buffers | Native `buffa::sensitive::List`, including numeric slots and outgrown allocations | Growth, clone and clear/drop observations |
| Retained unknown-field cleanup and recursive typed checks | `unknown_fields=false`; explicit zero-allowance wire admission; unknown data cannot inhabit a typed message | Nested/group/unknown wire rejection and complete-tree admission |
| Ordinary JSON base64 scratch | Local `ProtoBytesJson` reserves guarded storage before decoding; wipes encoded owned strings and serialization scratch | Standard and URL-safe padding vectors, malformed base64, optional/repeated fields and allocation tests |
| View export policy | `deny_view_json=.reallyme.cose.v1`, including empty and containing views | Whole-view export rejection, eager and owned oneof redaction, owned JSON compatibility |
| Native closed, payload and borrowed callback enums | Typed `(buffa.ext.file).adapters` options; Buffa emits 17 closed selectors, two payload selectors and five borrowed enums | Direct Buffa output comparison; unknown/zero and normalization tests; incomplete descriptors, duplicate identities and missing callback payload tests |
| Native record projections, constants, reason aliases and equality compatibility | Separate schema-derived companions; no enum generation or semantic rewriting of Buffa output | Operation/type reachability and regeneration tests |
| Canonical protobuf and domain validation | Retained bounded codecs, re-encoding checks, typed errors and provider authorization | Existing native/protobuf/JSON parity and independent vectors |
| Transport, parser and borrowed input ownership | Retained source owners and JSON escape rejection; serialized copies remain caller-owned | Existing size/recursion/encoding/ownership tests |

Every cloned secret field owns and wipes its own allocation. The executable COSE
boundary decodes fresh owned messages and drops them on error. Integrations that
merge into an existing destination can opt into `clear_on_merge_error()` to wipe
it on failure. Standard owned views retain shared `Bytes` backing. COSE operation
execution uses owned messages and wipe-owned output buffers. Integrations that
need private wiping view storage can use `GuardedOwnedView` over their own input
allocation. Native message cleanup does not erase caller copies or JSON parser
scratch.

No lazy view, map, reflection or imported WKT tree is generated here. Adding an imported tree requires the
guarded imported family, feature and inspection configuration before admission;
ordinary WKTs and dynamic reflection snapshots do not satisfy cleanup policy.

## Generation

The `buffa` dependency resolves to `reallyme-buffa =0.1.2` with `json` and
`zeroize`. Buf 1.75.0 invokes `reallyme-protoc-gen-buffa =0.1.3` and
`reallyme-protoc-gen-buffa-packaging =0.1.3`. The generator writes the message,
enum, oneof, eager-view and module files under `crates/proto/src/generated/buffa`.
The driver copies Buffa's 24 native enum files to the implementation crate and
formats all generated Rust with `rustfmt`. No semantic source patches are applied.
It also checks the schema-derived companions in
`crates/proto/src/contract_extensions.rs` and `crates/cose/src/generated_contract`.

Buffa 0.1.3 emits fixed diagnostics for unknown names, unknown numbers and
out-of-range numbers. Tests cover signed and unsigned input, known values, null
defaults, lenient field parsing and unknown values in open enum fields.
Regeneration uses the generator output directly and formats it with `rustfmt`.

The remaining companion generation handles native record projections (including
checked `usize` limits), constants, error spelling aliases, equality compatibility
and module assembly. It emits no enums. These record and alias projections are
not supplied by Buffa 0.1.3; removing this companion code would require further
Buffa support or a separately approved Rust API change. Freshness and reachability
checks cover both Buffa output and these companions.

The imported option descriptor is vendored unchanged under
`crates/proto/proto/buffa`, with its upstream license and content digest. Only
COSE files are generation targets. The published protobuf crate includes the
import descriptor and license. The option
messages are build-time descriptors and are not added to the public wire crate.
