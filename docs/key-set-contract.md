# COSE_KeySet

The generated `key_set_parse` and `key_set_create` operations implement the
nonempty key array defined by RFC 9052 section 7. Each request requires a
projection and an explicit key-type allowlist. The limits are 64 members,
16 KiB per member, 32 parameters per map and 1 MiB per encoded set.

Parsing frames the complete definite-length input and rejects trailing data.
It processes each member independently, returning its source index and either
a key or a fixed `CoseErrorReason`. Invalid or unsupported members do not hide
valid neighbours. Creation requires every supplied member to be accepted.

`SENSITIVE_STORAGE` retains each accepted map exactly, including unsorted map
order, private parameters and opaque extensions. Both requests and results own
sensitive bytes with generated redaction and zeroization. `PUBLIC_PARAMETERS`
constructs a new map containing only the selected key type's public parameters
and its optional algorithm. It removes private parameters, extensions, key
identifiers, key operations and Base IV. Symmetric keys have no public projection.

These operations validate the format of OKP, EC2, RSA, symmetric and AKP keys.
They do not validate mathematical key properties, establish trust or authorize
operations. Import a selected key through the operation-specific validation
contract before cryptographic use. A public projection is a representation of
public identity, not a preservation of key-usage policy.

| Requirement | API and focused test |
| --- | --- |
| RFC 9052 section 7 array and independent member processing | `key_set_parse`; `key_set_processes_bad_unknown_and_disallowed_members_independently` |
| Exact received maps, including unsorted RFC example | `SENSITIVE_STORAGE`; `key_set_roundtrips_rfc_public_map_with_exact_unsorted_bytes_and_projections` |
| Public projection strips private and unknown extension fields | `PUBLIC_PARAMETERS`; `key_set_projection_drops_private_parameters_and_opaque_secret_extensions` |
| Limits, complete framing, sensitive ownership | Both operations; `key_set_boundaries_and_sensitive_clear_are_explicit` |

The public-key fixture is independently specified in
[RFC 9052 appendix C.7.1](https://www.rfc-editor.org/rfc/rfc9052.html#appendix-C.7.1).
The same focused tests run natively and under Node's WASM test harness.
