# Exact Sign1 algorithm and key binding

Curve/key encoding checks cannot establish that a key is authorized for a
particular COSE registration. ES256 (`-7`) can use the same P-256/SHA-256
combination as ESP256 (`-9`), while retaining separate protocol identities.
[RFC 9864 §2.1](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.1)
defines the distinct fully specified registration. A credential store or signing
permission can authorize one registration independently of the other. Key
selection must preserve that distinction even if the public point and `kid`
are identical. This policy boundary does not depend on a signature-forgery
attack or on reinterpreting points across curves.

## Rust migration

Every native Sign1 resolver now receives the exact `CoseSignatureAlgorithm`.
This includes `cose_verify1`, its metadata/policy/detached variants and
`cose_verify1_with_x5chain`. The previous `Algorithm` callback parameter is a
deliberate source break. All callbacks accept `FnOnce`, allowing a
single owned key to move into verification. Existing `_with_exact_algorithm`
entrypoints remain available with equivalent semantics.

Key stores resolve `(exact_registration, protected_kid)` as one authorized
identity. Certificate callbacks resolve the exact registration and validated
certificate identity. Do not collapse the registration back to a primitive
before authorization. `CosePolicy` independently restricts which registrations
the operation permits. Its historical modern defaults remain unchanged.

Native receipts retain `cose_algorithm`, and protobuf receipts retain
`exact_signature_algorithm`, for exact authenticated identity. Compatibility
primitive metadata remains useful for crypto dispatch and cannot establish
credential authorization.

## Protobuf migration

`sign1_verify` and `sign1_verify_detached` require `public_key_algorithm` for
the directly supplied public key. `sign1_verify_profile` has the same rule
when no resolver capability is present. The algorithm is authorized by the
caller rather than inferred from the point encoding, the received header or
an allowlist. Populate it from the credential/key's trusted registration.

| Condition | Fixed reason |
| --- | --- |
| Missing/UNSPECIFIED direct-key registration | `COMMON_INVALID_PARAMETER` |
| Unknown registration selector | `COMMON_INVALID_PARAMETER` |
| Configured key registration differs from protected `alg` | `KEY_ALGORITHM_MISMATCH` |
| Registration outside the modern profile or operation allowlist | `COMMON_UNSUPPORTED_ALGORITHM` |
| Exact resolver declines the `(registration, kid)` identity | `SIGN1_KEY_NOT_RESOLVED` |

An exact-registration resolver capability supports several algorithms without
requiring the caller to parse the untrusted protected header first. It always
receives the exact registration and `kid`; it must authorize both. A certificate
callback returns a working-key suite and selected DER, which COSE binds to
the protected registration and received leaf. In these callback-aware operations,
`public_key_algorithm` is an optional additional filter. A mismatch fails before
the callback. An omitted filter does not remove the callback's exact binding.

The deprecated protobuf `ECDSA_P256_SHA256` selector denotes ESP256, including
when used as a key binding. It does not authorize ES256. This migration retains
all field numbers, wire registrations, signed bytes, external AAD rules and
existing certificate ownership/leaf checks. It deliberately changes acceptance
of unbound direct-key requests and the primitive-only Rust callback signatures.

## Focused evidence

`contract_sign1_key_binding_tests.rs` runs natively and in WASM, including
binary protobuf and ProtoJSON parity:

- Every native callback name receives exact ES256/ESP256 identity.
- The same P-256 public key and `kid` cannot cross a resolver's authorization.
- Direct attached/detached requests reject missing, unknown and mismatched bindings.
- Exact profile resolvers support multiple algorithms and reject mismatched filters
  before invoking a provider.
- Direct profile requests cannot omit their key binding.
- Both native certificate callback names retain exact registration.
- The deprecated P-256 selector permits ESP256 and rejects ES256.

Existing independent ES256, Sign1, certificate, malformed-input and limit vectors
continue to exercise the same authenticated bytes and crypto boundary.
