# ISO/IEC 18013-5:2021 signature verification

The `iso18013` Rust module provides an explicit COSE verification boundary for
the original signature registrations used by the 2021 ISO profile. It accepts
attached issuer content and detached device or reader content, preserves the
received protected header byte string, and fixes external AAD to the empty byte
string. Callers must supply an exact algorithm/curve allowlist and a verifier
bound to a validated key. There is no unrestricted default allowlist.

This module does not change `CoseSignatureAlgorithm`, `CosePolicy`, the modern
COSE_Key profile, or the protobuf operation contract. In particular, the modern
API continues to reject `-35`, `-36`, and `-8`. The ISO profile does not replace
these identifiers with ESP384 (`-51`), ESP512 (`-52`), or Ed25519 (`-19`).

The additional [signed-container contracts](signed-container-contracts.md) provide
separate source-specific certificate, container, key-inspection and signing APIs;
they enforce the ISO algorithm/curve table in addition to family compatibility.

## Registrations and key curves

[RFC 8152 §§8.1–8.2](https://www.rfc-editor.org/rfc/rfc8152.html#section-8.1)
defines ES256 (`-7`) as ECDSA/SHA-256, ES384 (`-35`) as ECDSA/SHA-384, ES512
(`-36`) as ECDSA/SHA-512, and EdDSA (`-8`) as pure EdDSA. These registrations
require a separately selected key curve. `Iso18013SignatureSuite::new` checks
signature-family compatibility; the application allowlist authorizes individual
pairs according to its applicable acceptance policy.

The curve identifiers below come from the
[IANA COSE Elliptic Curves registry](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves).
Coordinate length is a format check, never a way to identify or substitute a
named curve. X25519 (`4`) and X448 (`5`) are agreement curves and are rejected
by this signature boundary. An available X448 primitive does not establish
reader agreement integration.

## Provider coverage

Production cryptographic imports come exclusively from `reallyme-crypto`.
The built-in adapter uses its existing key-validation, signature-conversion,
and dispatch boundaries. This table describes the pinned `0.4.2` adapter,
with the same coverage in native and WASM builds.

| Key curve | COSE curve ID | ES256 (`-7`) | ES384 (`-35`) | ES512 (`-36`) | EdDSA (`-8`) |
| --- | ---: | --- | --- | --- | --- |
| P-256 | 1 | Built in | External provider required | External provider required | Incompatible family |
| P-384 | 2 | External provider required | Built in | External provider required | Incompatible family |
| P-521 | 3 | External provider required | External provider required | Built in | Incompatible family |
| brainpoolP256r1 | 256 | External provider required | External provider required | External provider required | Incompatible family |
| brainpoolP320r1 | 257 | External provider required | External provider required | External provider required | Incompatible family |
| brainpoolP384r1 | 258 | External provider required | External provider required | External provider required | Incompatible family |
| brainpoolP512r1 | 259 | External provider required | External provider required | External provider required | Incompatible family |
| Ed25519 | 6 | Incompatible family | Incompatible family | Incompatible family | Built in |
| Ed448 | 7 | Incompatible family | Incompatible family | Incompatible family | External provider required |

For compatible pairs without a built-in implementation,
`Iso18013CryptoVerifier::new` and `from_cose_key` return the fixed
`CoseError::ProviderUnavailable`. They never try an identically sized curve or
choose another hash. Incompatible signature families return
`CoseError::UnsupportedAlgorithm`. `has_builtin_provider` reports this adapter
matrix and does not authorize a pair or establish complete reader coverage.

`Iso18013Verifier` is the integration boundary for additional crypto providers.
A provider must validate the actual named curve, subgroup/point encoding,
optional key-level `alg`, and verification key operations before reporting its
suite. Verification receives the complete `Sig_structure` and raw, exact-width
COSE signature. An ECDSA provider must select the suite's SHA-2 hash independently
of the curve and perform the applicable ECDSA digest conversion. An EdDSA provider
must use pure EdDSA with empty context. Provider failures must use fixed
`CoseError` variants and must not contain key bytes or backend text.

The crypto repository owns additional production providers. Completing its
brainpool, Ed448, and additional ECDSA hash/curve routes requires independent
vectors, malformed/weak-key rejection, subgroup and point validation, scalar
range checks, and native/WASM coverage. A broad dependency feature group is not
evidence that those routes execute. Agreement providers and reader integration
remain separate from this signature module.

## Input and ownership contract

All ISO role entrypoints in this module require an untagged four-element
COSE_Sign1 array. The issuer role requires an attached byte-string payload;
device and reader roles require a null payload slot and caller-supplied exact
detached content. The request has no external-AAD override.

The protected algorithm must be an original integer registration. Header
labels must be unique within and across buckets. Content types accept unsigned identifiers or bare RFC 6838 media types, without
MIME parameters; IV and countersignature headers are rejected. Unprotected `alg` is rejected;
an unprotected `kid` is an unused hint and never appears in authenticated
metadata. Critical headers are rejected. Bounded RFC 9360 `x5chain` values can
appear in either header bucket, but neither their presence nor signature success
establishes certificate trust. Other noncritical extensions are retained in the
original protected bytes without interpreting their application semantics.

The Sign1 and ISO COSE_Key boundaries enforce definite lengths, preferred
integer/length widths, unique map labels, bounded collections/nesting, and full
input consumption. They accept unsorted map orders, including inside protected
byte strings. ISO public-key import checks `kty`, the exact named `crv`, optional
original `alg`, verification `key_ops`, coordinate lengths, and public point
validity for available providers. It accepts an optional byte-string Base IV
(label 5) within the key size limit. The parameter has no effect on verification.
The caller retains the original encoding, and signature-purpose peer-key
inspection can return it with the validated public material. ISO import rejects
private material. The modern COSE_Key deterministic-map-order requirement is
unchanged.

Hard limits are 65,536 encoded Sign1 bytes, 1,048,576 payload bytes, 16,384
encoded COSE_Key bytes, 32 parameters per ISO key or header map, 1,024 items per
collection, and 32 nesting levels per decoded CBOR boundary. Application Sign1
limits can lower the byte maxima, but cannot raise them. Certificate limits use
the existing shared `x5chain` profile.

Decoded trees acquire a recursive wipe owner before semantic interpretation.
Certificate shape and limits are checked while borrowing that tree. The
authentication structure, imported keys, returned protected bytes, identifiers,
and attached payloads use zeroizing owners. Result and key owners have no
formatting, cloning, or serialization implementations. Detached payloads and
original input buffers remain caller-owned and must be cleared by their owners
when sensitive.

## Reader and format responsibilities

This is a signature primitive boundary, not a claim of complete ISO reader
conformance. A shared format contract must separately represent device signature
and MAC choices, retain bounded exact encoded spans, and verify its complete
ISO 8.1 encoding profile. Ordinary decoder acceptance alone does not prove that
profile. Response status rules, including exclusion of documents on nonzero
status, belong to format validation and reader policy.

The reader must construct and bind the exact issuer, device, and reader
authentication content; validate certificate paths and trust; and enforce
document type, transcript, key authorization, validity, and acceptance policy.
This module does not re-encode those application inputs or parse their ISO
semantic content. No sibling format or crypto repository is changed by this
COSE implementation.

## Independent evidence

`crates/cose/tests/fixtures/iso18013-sign1.json` contains independently encoded
COSE and `Sig_structure` bytes signed and verified with Python cryptography
50.0.2 and OpenSSL 4.1.0, using synthetic public test material. Its protected
maps deliberately put `kid` before `alg`.

Native and WASM tests execute the four built-in pairs. A test-only provider
using direct RustCrypto dependencies verifies all nine NIST ECDSA hash/curve
pairs against the same OpenSSL fixtures, demonstrating the separately selected
hash and curve contract. That provider is not included in production code.
Tests cover changed payloads, AAD, protected order, signatures, valid wrong keys,
registration substitution, key algorithm/curve/usage mismatch, malformed and
excessive inputs, and missing providers. These tests do not claim production
brainpool or Ed448 provider coverage.
