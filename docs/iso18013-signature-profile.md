# ISO/IEC 18013-5:2021 Sign1 verification

Use `cose_verify_iso18013_sign1` with an explicit algorithm/curve allowlist and
an `Iso18013Verifier` bound to a validated key. Issuer content is attached;
device and reader content is detached with a null payload slot. Envelopes are
untagged, external AAD is always empty, and the received protected bytes enter
`Sig_structure` unchanged.

Original ES256 (`-7`), ES384 (`-35`), ES512 (`-36`) and EdDSA (`-8`)
registrations remain distinct from ESP256 (`-9`), ESP384 (`-51`), ESP512
(`-52`) and Ed25519 (`-19`). The modern Sign1 profile retains its own algorithm
rules and defaults.

`Iso18013SignatureSuite::new` checks signature-family compatibility. The caller
must authorize the permitted hash/curve pairs. Use the
[signed-container profile](signed-container-contracts.md) when COSE should also
enforce the ISO pair table.

## Provider support

The built-in adapter supports ES256/P-256, ES384/P-384, ES512/P-521 and
EdDSA/Ed25519 in native and WASM builds. Other compatible hash/curve pairs
require an `Iso18013Verifier` backed by a crypto provider. `has_builtin_provider`
reports built-in availability, not authorization.

| Curve | COSE curve ID | Built-in signature support |
| --- | ---: | --- |
| P-256 | 1 | ES256 |
| P-384 | 2 | ES384 |
| P-521 | 3 | ES512 |
| brainpoolP256r1 | 256 | External provider required |
| brainpoolP320r1 | 257 | External provider required |
| brainpoolP384r1 | 258 | External provider required |
| brainpoolP512r1 | 259 | External provider required |
| Ed25519 | 6 | EdDSA |
| Ed448 | 7 | External provider required |

X25519 and X448 are agreement curves and cannot be used for signatures.
Missing built-in coverage returns `ProviderUnavailable`; incompatible families
return `UnsupportedAlgorithm`. A provider must validate the named key and its
usage, report the exact suite, and verify raw COSE signatures. ECDSA selects
the suite's hash independently of the curve. EdDSA uses pure mode with empty
context.

## Input and caller obligations

Headers must have unique labels within and across buckets. `alg` must be
protected. Critical headers, IV and countersignature headers are rejected.
Unprotected `kid` is a discovery hint, not authenticated identity. An `x5chain`
can appear in either bucket; signature success does not establish path trust.
Other accepted noncritical extensions retain their received encoding.

Public COSE_Key import accepts unsorted unique maps and checks the exact curve,
optional algorithm, verification `key_ops`, public-only material and point
validity. Optional Base IV must be a byte string; it does not affect signatures.
The generic signing-key parser retains its separate sorted-map requirement.

The default encoded Sign1 budget is 65,536 bytes; an explicit budget can select
up to 1,048,576 bytes. Payloads are bounded at 1,048,576 bytes, keys at 16,384
bytes and key/header maps at 32 parameters. Shared CBOR and certificate limits
also apply. See [CBOR rules](cbor-boundary.md).

Receipts and imported key owners wipe their buffers on drop. Callers retain
responsibility for input and detached-content buffers. Construct authentication
content and transcripts exactly, and validate ISO schemas, certificate trust,
document type, validity, key authorization and replay policy separately.

P-256, P-384 and P-521 verification accepts high-S ECDSA; secp256k1 requires
low-S. Do not deduplicate or detect replay using a hash of COSE bytes. Use an
authenticated message identity within the protocol context.
