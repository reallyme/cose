# Public key encoding

`cose_key_to_public_vec` emits a canonical public identity projection from a
validated `CoseKey`. The protobuf operation is `key_to_public_vec` (2013), with
`CoseKeyBytesRequest` and `CoseKeyBytesResult`. Native, protobuf and JSON callers
use the same validation and encoding implementation.

The result contains only the supported key family's public parameters and the
exact algorithm registration, when supplied. An absent `alg` remains absent.
EC2 public points use the canonical compact representation. Private parameters,
all opaque extensions, `kid`, `key_ops` and Base IV are excluded. This operation
projects public identity; it does not transport the input's usage restrictions,
trust decisions or original byte representation.

Use this operation when publishing a public COSE_Key. An unknown text parameter
such as `"d"` can carry arbitrary private bytes even in an otherwise public key.
Its contents are never copied into the public projection. A real private key
parameter is excluded too, after the complete input key and its public binding
have been validated.

`cose_key_to_vec` serializes the complete validated owner, including private and
extension parameters. Its output is sensitive. It remains available for full
key storage and roundtrips, and must not be treated as a public-key export.
Neither encoder replaces received authenticated bytes or transcript inputs.

| Contract | API | Regression coverage |
| --- | --- | --- |
| No private or extension bytes in published keys | `cose_key_to_public_vec`, operation 2013 | `contract_public_key_vec_tests.rs`: OKP, EC2, ML-DSA, X25519 and ML-KEM, with real private parameters and a text-label secret |
| Exact registration and absence | Same operation | Independent RFC 8032 public-map bytes; ES256 and ESP256 remain distinct; omitted alg is preserved |
| Stable public identity | Public projection, kid and Multikey | Same kid and Multikey with and without extensions; projection is idempotent; full owned bytes remain unchanged |
| Deterministic boundaries | Generated request/result and fixed errors | Native/protobuf/JSON parity, malformed and oversized input, request/result route pairing, native/WASM execution |
