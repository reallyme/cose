# Protobuf presence in 0.3.0

Version 0.3.0 replaces manual presence flags with protobuf presence. Regenerate
consumers against the 0.3.0 schema and update producers and consumers together.
The package remains `reallyme.cose.v1`; this is a deliberate pre-1.0 contract
change, not a change to authenticated COSE encodings or algorithm registrations.

| Message | Value field and number | Reserved flag number and name |
| --- | --- | --- |
| `CoseSign1CreateRequest` | `optional bytes kid = 4` | 5, `has_kid` |
| `CoseSign1CreateDetachedRequest` | `optional bytes kid = 4` | 5, `has_kid` |
| `CoseKeyFromPrivateBytesRequest` | `optional bytes public_key = 3` | 4, `has_public_key` |
| `CoseMlKemEncryptRequest` | `optional bytes supp_priv_info = 7` | 8, `has_supp_priv_info` |
| `CoseMlKemDecryptRequest` | `optional bytes supp_priv_info = 5` | 6, `has_supp_priv_info` |
| `CoseMac0VerifyResult` | `optional bytes protected_kid = 3` | 4, `has_protected_kid` |
| `CoseIsoSign1VerifyResult` | `optional bytes protected_kid = 3` | 4, `has_protected_kid` |
| `CoseIsoSign1VerifyResult` | `optional bytes attached_payload = 5` | 6, `has_attached_payload` |
| `CoseContainerVerifyResult` | `optional bytes certificate_sha256 = 10` | 11, `has_certificate_sha256` |
| `CoseSign1VerifyResult` | `exact_signature_algorithm = 4`; zero means absent | 5, `has_exact_signature_algorithm` |
| `CoseKeyBytesResult` | `signature_algorithm = 2`; zero means absent | 3, `has_signature_algorithm` |

ReallyMe Buffa 0.1.2 generates `Option<SecretBytes>` for optional bytes. `None` omits the
field; `Some(SecretBytes::default())` writes its tag and a zero length. Borrowed generated
views expose `Option<&[u8]>`. Adapters borrow that presence directly, and all
owning buffers retain redacted Debug and wipe-on-drop behavior. Clear, generated
builder replacement, repeated binary fields and failed JSON decoding also wipe
sensitive buffers. Owned base64 strings transferred by a JSON deserializer
also wipe on success and failure. Native generator configuration derives these shapes from the schema and
routes every field through the guarded representation and JSON policy.

ProtoJSON omits an absent value and encodes a present empty value as `""`.
A JSON `null` is absent, following ProtoJSON semantics. Producers supply only
`"kid"`, `"publicKey"` or `"suppPrivInfo"`, without a second flag. The COSE
operation still decides whether the supplied value is valid: signing rejects
a present empty kid, while an empty private KDF context is valid and distinct
from no private KDF context. A verified empty attached payload remains present;
detached receipts omit that field. A present certificate SHA-256 must have
exactly 32 bytes. Unknown enum values remain typed failures.

The byte-field numbers and length-delimited wire types are retained. Nonempty
values keep their encodings. Presence of an empty value changes its encoding:
old implicit fields omitted it, while new optional fields encode it. A legacy
flag cannot recover an empty value once that value was omitted. Executable
boundaries reject retired binary or JSON flags as unknown fields; they do not
silently reinterpret legacy flag/value pairs. The default generated protobuf decoder can discard unknown fields. The
executable boundary rejects them on the original encoded bytes.

`buf lint` passes. Against published 0.2.11's schema, the unmodified Buf `FILE`
check reports 12 intentional compatibility changes: seven retired flags and
five implicit-to-explicit presence changes. The other four byte fields and
four flags belong to the unreleased ISO/container contract. All 11 retired
flag numbers and names are reserved. No Buf rule or file exclusion has been
added to hide these changes; consumers must take the 0.3.0 migration explicitly.

`crates/proto/tests/presence_tests.rs` pins all nine optional byte encodings,
JSON absent/null/empty/nonempty behavior, generated views, replacement, clear,
malformed fields and late decoding failures. Native and WASM operation tests
exercise real signing, private-KDF-context authentication in both ML-KEM modes,
and empty attached versus detached ISO receipts. Existing independent COSE
fixtures and known answers remain unchanged.

`crates/proto/tests/json_owner_tests.rs` observes live synthetic allocations
immediately before release. It checks owned base64 strings, optional-buffer
clear/drop, builder replacement, growing binary replacement and malformed
partial merges. These guarantees cover message-owned buffers and strings
delivered to the sensitive-field visitor. Callers manage the lifetime and erasure
of source JSON, DOM storage and serialized copies.
