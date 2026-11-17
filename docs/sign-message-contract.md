# COSE_Sign

The generated `sign_create` and `sign_verify` operations implement RFC 9052
sections 4.1 and 4.4. They accept attached or explicitly supplied detached
content, explicit external AAD and a nonempty suite allowlist. `sign_verify`
requires one caller-authorized, indexed key for every signature and verifies
all signatures before returning payload or authenticated metadata. Threshold
policy, key discovery and certificate trust remain application responsibilities.

The exact body and signer protected byte strings enter the `Signature`
authentication structure. Empty protected bytes and an encoded empty map stay
distinct. The implementation uses reallyme-codec to frame and emit definite,
preferred CBOR without sorting received maps. It rejects trailing data,
duplicate or conflicting headers, unprotected algorithms, unknown critical
parameters, wrong content modes and algorithm/key mismatches. An algorithm can
be protected by the body or by an individual signer, but cannot be repeated.
Unprotected identifiers are never returned as authenticated signer identities.

Limits are 32 signatures, 32 labels and 16 KiB per header bucket, 64 KiB of AAD,
and 1 MiB per complete encoded message or authentication structure. Encodings
are measured and reserved fallibly by codec. Generated sensitive owners redact
and wipe keys, payloads, signatures and exact header bytes.

The suite combines the exact COSE registration and key curve. Built-in crypto
coverage includes ES256/P-256, ES384/P-384, ES512/P-521, EdDSA/Ed25519, the
separate ESP256/384/512 and Ed25519 registrations, ES256K and ML-DSA-44/65/87.
ML-DSA suites use the unspecified curve selector. Recognized legacy pairs with
missing crypto coverage fail with the fixed provider-unavailable reason.
No algorithm is enabled implicitly. The existing explicit ISO Sign1 profiles
remain separate and retain their compatibility rules.

**High-S ECDSA is accepted for P-256, P-384 and P-521 by the built-in
verifiers; secp256k1 enforces low-S.** COSE permits high-S signatures under
[RFC 9053 section 2.1](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1).
Both `(r, s)` and `(r, n-s)` can verify for the same message and key, where `n`
is the curve's subgroup order. ECDSA signatures are therefore malleable.
**Never deduplicate messages or detect replays using a hash of the COSE bytes.**
Use a stable authenticated message identity within the application's protocol
context.

| Requirement | Focused native/WASM test |
| --- | --- |
| RFC 9052 C.1.1 and C.1.2 independent single/multiple signatures | `sign_rfc_single_and_multiple_signatures_verify_exact_bytes` |
| Attached/detached content and exact unsorted protected bytes | `sign_create_attached_detached_and_shared_body_algorithm` |
| Payload, AAD, signature, binding, trailing-data failures | `sign_rejects_tampering_wrong_binding_critical_duplicates_and_trailing_data` |
| Exact registration/curve binding for every built-in suite | `sign_all_builtin_suites_keep_exact_registration_and_curve` |
| Published protobuf compatibility aliases retain one exact identity | `sign_compatibility_aliases_do_not_create_a_second_algorithm_identity` |
| Header types, duplicates, critical parameters and AAD bound | `sign_header_and_resource_failures_are_fixed` |

Independent vector source: [RFC 9052 appendix C](https://www.rfc-editor.org/rfc/rfc9052.html#appendix-C).
