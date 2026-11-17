# RFC 9338 countersignatures

The generated contract defines separate full and abbreviated V2 creation and
verification operations, plus a format-only attachment operation. A target
selects its exact COSE structure, envelope policy, received bytes and optional
detached content. Algorithms, curves, keys and allowlists are explicit.

Full countersignatures contain protected headers, unprotected headers and a
signature; standalone counters can be tagged 19. They can be verified from a
standalone value or by index in unprotected header 11. Abbreviated counters
are encoded byte strings and use caller-supplied algorithm/key context. They
can be verified standalone or from unprotected header 12. No algorithm is
silently taken from the primary signature, encryption or MAC operation.
The indexed key binding must match the selected full counter, or be zero for
a standalone/abbreviated counter.

**High-S ECDSA is accepted for P-256, P-384 and P-521 by the built-in
verifiers; secp256k1 enforces low-S.** COSE permits high-S signatures under
[RFC 9053 section 2.1](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1).
Both `(r, s)` and `(r, n-s)` can verify for the same message and key, where `n`
is the curve's subgroup order. ECDSA signatures are therefore malleable.
**Never deduplicate messages or detect replays using a hash of the COSE bytes.**
Use a stable authenticated message identity within the application's protocol
context.

Targets include Sign, Sign1, Signature, Encrypt, Encrypt0, Mac, Mac0, Recipient
and a full countersignature for chaining. The implementation extracts the
protected bytes, second logical byte-string field and any following root
byte-string fields. It never asks callers to invent `other_fields`.

| Target layout | Full context | Abbreviated context | `other_fields` |
| --- | --- | --- | --- |
| Sign, Signature, Encrypt, Encrypt0, Recipient, full counter | `CounterSignature` | `CounterSignature0` | Absent |
| Sign1 | `CounterSignatureV2` | `CounterSignature0V2` | Primary signature |
| Mac, Mac0 | `CounterSignatureV2` | `CounterSignature0V2` | Primary tag |

Abbreviated structures omit `sign_protected` entirely. An empty placeholder
would produce a different, invalid preimage. Target and counter protected bytes
remain exact, including empty-versus-encoded-empty maps and unsorted map order.
Detached content requires a null slot. Floating-point values cannot stand in
for null or for a signature/tag byte string.

Attachment adds or appends a full counter under header 11, or adds a single
abbreviated counter under header 12. It preserves every other primary field's
complete received encoding. An existing abbreviated counter cannot be
replaced. Deprecated headers 7/9 are rejected by the V2 contract. Attachment
establishes no authentication; verification is a separate operation.

Counter verification authenticates the extracted target bytes. It does not
verify the target's primary cryptography, authorize a signer or establish trust.
Primary critical-header semantics remain that operation's responsibility;
counter critical semantics are enforced for the selected counter. As RFC 9338
section 6 explains, short primary MAC/AEAD tags also limit the collision strength
of a countersignature. Applications choose their required security profile.

The general encoding profile is definite preferred CBOR with received map
order. Limits are 1 MiB per message/authentication structure, 64 KiB of counter
AAD, 16 KiB and 32 labels per header bucket, 32 full counters per header and
the shared codec nesting/work bounds. Secret-bearing requests and results use
generated wipe-owned bytes, redacted formatting and wipe on clear/drop or
replacement. Fixed schema reasons cover format, policy, key, provider,
authentication and resource failures. RSA verification supports explicit
PS256/384/512 and RS256/384/512 suites with SPKI keys; RSA counter creation
returns `PROVIDER_UNAVAILABLE`. See [RSA verification](rsa-verification.md).
Other crypto suite coverage is the same as the
[general Sign contract](https://github.com/reallyme/cose/blob/main/docs/sign-message-contract.md).

| Requirement | Focused native/WASM test |
| --- | --- |
| All six literal RFC 9338 appendix A examples | `counter_all_six_independent_rfc9338_examples_verify_embedded_v2` |
| Both abbreviated contexts and exact independent signatures | `counter_abbreviated_independent_openssl_vectors_cover_both_contexts` |
| Every target kind and chaining | `counter_full_and_abbreviated_creation_support_every_target_and_chaining` |
| Attachment, indexed selection and primary-byte preservation | `counter_attachment_preserves_primary_fields_and_selects_full_collections` |
| Changed content, primary tag, AAD, counter signature and registration | `counter_tampering_payload_other_fields_aad_key_and_protected_bytes_fail` |
| Exact counter headers, wrong key, widths and indexed binding | `counter_exact_protected_bytes_wrong_key_width_and_index_are_enforced` |
| Detached content, malformed floats/nulls, deprecated headers and trailing data | `counter_detached_content_is_explicit_and_never_replaces_attached_data`; `counter_rejects_legacy_headers_malformed_slots_trailing_data_and_wrong_source` |
| Missing providers, zeroization, maximum counter count and encoded input | `counter_provider_limits_and_sensitive_ownership_fail_closed`; `counter_collection_boundaries_and_oversized_inputs_are_fixed` |

Full independent examples are extracted literally from the
[RFC 9338 XML](https://www.rfc-editor.org/rfc/rfc9338.xml).
Abbreviated fixtures contain fixed section 3.3 preimages and signatures computed
independently with Node's OpenSSL Ed25519 and RFC 8032 test key 1. That independent
calculation also reproduces the published full signatures in RFC 9338 A.4.1 and
A.5.1. Older working-group abbreviated examples use deprecated structures;
they are not treated as V2 positive vectors.
