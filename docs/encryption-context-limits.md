# Private encryption context limits

The ReallyMe ML-KEM encryption profile accepts up to 65,483 bytes of
`SuppPrivInfo`, independently of plaintext and external AAD. Both native and
generated encryption/decryption operations enforce this bound before KEM work.
Overflow returns `COMMON_RESOURCE_LIMIT_EXCEEDED`; it is not an authentication
failure or a provider error.

The implementation derives the bound with checked subtraction from
`reallyme-crypto`'s `KMAC256_MAX_CONTEXT_LENGTH`, currently 65,536 bytes. The
complete encoded KDF context reserves 53 bytes: 42 recipient protected-header
bytes, the outer and SuppPubInfo arrays, AlgorithmID, the output-bit length and
both byte-string headers. A 256-bit output length needs three CBOR bytes; the
128/192-bit lengths need two. The common bound therefore covers every supported
ML-KEM, direct/key-wrap and AES-GCM combination. A 65,484-byte private value fits
some shorter-output contexts but exceeds the largest supported context budget.

The KDF repeats the input check and validates the final encoded context against
crypto's limit. Absent and present-empty values remain distinct, and accepted
context bytes and derived keys are unchanged. COSE continues to preserve the
received protected-header bytes for the KDF.

| Requirement | API / implementation | Coverage |
| --- | --- | --- |
| Shared usable ceiling | Encrypt/decrypt request validation, `kdf::validate_supp_priv_info` | All six recipient profiles and all content key lengths; exact encoded 52/53-byte overhead |
| Reject before expensive work | Native and protobuf encrypt/decrypt operations | One byte over the limit rejects before key/envelope checks; native allocation counter observes no allocations for otherwise valid requests |
| Boundary interoperability | Direct and key-wrap ML-KEM with AES-128/192/256-GCM | Maximum-size roundtrips across all 18 combinations, deterministic decrypt metadata and typed native/protobuf/JSON errors, native/WASM |
