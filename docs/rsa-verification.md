# Explicit COSE RSA verification

RSA verification uses published `reallyme-crypto` 0.4.2 exclusively.
`reallyme-codec` 0.4.3 owns strict DER and CBOR admission. Protobuf and the
ReallyMe Buffa 0.1.2 generated contract define the public operations and owners.

| Registration | COSE identifier | Fixed verification parameters |
| --- | --- | --- |
| PS256 | -37 | SHA-256, MGF1 SHA-256, 32-byte salt |
| PS384 | -38 | SHA-384, MGF1 SHA-384, 48-byte salt |
| PS512 | -39 | SHA-512, MGF1 SHA-512, 64-byte salt |
| RS256 | -257 | PKCS#1 v1.5, SHA-256 |
| RS384 | -258 | PKCS#1 v1.5, SHA-384 |
| RS512 | -259 | PKCS#1 v1.5, SHA-512 |

The distinct PSS and PKCS#1 v1.5 registrations are defined by
[RFC 8230 §2](https://www.rfc-editor.org/rfc/rfc8230.html#section-2) and
[RFC 8812 §2](https://www.rfc-editor.org/rfc/rfc8812.html#section-2).
PSS parameters never come from caller-controlled defaults or certificate
parameters. SHA-1 is outside this profile. Historical RS registrations require
explicit selection just as PSS does.

## Operations and key binding

`rsa_sign1_verify` (1019) verifies attached or detached Sign1 content. Requests
contain the complete encoded message, explicit envelope policy, exact selected
suite, caller-authorized public key, nonempty unique suite allowlist, external
AAD and optional expected protected `kid`. `signature_index` must be zero.
Presence of `detached_payload`, including an empty byte string, requires null
in the received payload slot. Absence requires an attached byte string.

`sign_verify`, `counter_signature_verify` and `counter_signature0_verify`
also accept these RSA suites in their existing indexed key-binding contracts.
Every RSA suite uses curve UNSPECIFIED. The public key is exactly one DER
`rsaEncryption` SubjectPublicKeyInfo; PKCS#1 public-key bytes, certificates,
private keys and automatic format detection are not accepted. Caller key
selection authorizes the exact registration and identity together. No key or
trust discovery is inferred from unprotected headers.

COSE enforces 2048..8192 modulus bits, including rejection of a 2047-bit key
whose signature width is still 256 bytes. Crypto additionally enforces public-key
constraints, exponent bounds, padding and signature verification. Signatures
must have exactly the modulus width. This profile does not adopt crypto's
historical 1024-bit document-verification allowance.

Protected-header contents are authenticated exactly as received; unsorted
unique maps retain their order. Changing the serialization of a protected
map invalidates its signature. Success returns a generated wiping owner with
the exact suite, protected bytes, protected `kid` and attached payload only.
Detached content remains caller-owned. Failed verification returns fixed
protobuf reasons without key, payload or backend diagnostics.

Limits are 1 MiB per message, content or authentication structure, 16 KiB and
32 labels per header bucket, 64 KiB AAD and 32 allowlisted suites. Shared CBOR
node/work limits also apply. Malformed/duplicate headers and unsupported
critical semantics fail closed. Metadata admission checks exact RSA identity,
curve, protected bytes and protected `kid` consistency before decoding results.

## Compatibility and remaining coverage

The existing modern and explicit ISO Sign1 profiles retain their accepted
algorithms, header rules and defaults. Their primitive `Algorithm` metadata
does not acquire a fabricated RSA selector. Applications select the generated
RSA operation explicitly. The same schema `CoseSignatureAlgorithm` and
`CoseSignatureSuite` are used throughout.

Crypto currently exposes RSA verification without a signing API. General Sign
and counter creation with RSA therefore fails with `PROVIDER_UNAVAILABLE`.
RSA signing, OAEP recipient processing and mathematical RSA COSE_Key import
are remaining gaps. KeySet's existing RSA support is structural storage/public
projection; it does not establish key validity or authorization. Certificate
path and reader protocol policy remain outside these operations.

## Independent and negative tests

`scripts/generate_rsa_vectors.py` uses OpenSSL only as a test oracle. It creates
temporary private test keys, verifies every generated signature independently
and writes only public keys, signatures and literal authentication structures
to `crates/cose/tests/fixtures/rsa.json`. Existing non-RSA vector files retain
their byte-for-byte expected outputs.

`contract_rsa_tests.rs` covers all six registrations, attached/detached and
empty content/AAD, exact protected bytes, wrong payload/AAD/header/signature/key,
PSS salt and MGF1 mismatches, suite/curve/`kid` authorization, weak/malformed
keys, signature lengths, malformed structures, duplicate/critical headers,
trailing bytes, ownership, result metadata and resource limits.
`contract_rsa_message_tests.rs` covers Sign, full and abbreviated V2 counters
and the fixed creation failures. Native and WASM/Node run typed, binary
protobuf and ProtoJSON parity. No mobile SDK or on-device execution is claimed.
