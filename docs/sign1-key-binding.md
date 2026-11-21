# Sign1 algorithm and key binding

Authorize the exact COSE registration with the key identity. ES256 (`-7`) and
ESP256 (`-9`) remain distinct even when they use the same P-256 point and `kid`.
Do not reduce a registration to a crypto primitive before key selection.

Native Sign1 resolvers receive `CoseSignatureAlgorithm` and the protected `kid`.
This includes the historical `cose_verify1` names and the
`_with_exact_algorithm` variants. Callbacks accept `FnOnce`. When migrating
older callers, replace primitive `Algorithm` callback parameters with exact
registration handling.

Direct protobuf Sign1 requests require `public_key_algorithm`. Set it from
trusted key metadata, not the received header or key encoding. A resolver
capability instead authorizes `(registration, kid)`; `public_key_algorithm`
can be an additional filter and is checked before invoking that provider.

| Failure | Reason |
| --- | --- |
| Missing or unknown direct-key registration | `COMMON_INVALID_PARAMETER` |
| Key registration differs from protected `alg` | `KEY_ALGORITHM_MISMATCH` |
| Registration outside the profile or allowlist | `COMMON_UNSUPPORTED_ALGORITHM` |
| Resolver declines the identity | `SIGN1_KEY_NOT_RESOLVED` |

Read `cose_algorithm` in native receipts or `exact_signature_algorithm` in
protobuf receipts for authenticated registration identity. Primitive metadata
is for dispatch, not authorization. The deprecated protobuf
`ECDSA_P256_SHA256` selector denotes ESP256 and does not authorize ES256.

Certificate callbacks receive the exact registration and certificate path.
Generated certificate providers also return the selected DER and working-key
suite; COSE checks both against the received leaf and protected algorithm.
Native key-only certificate resolvers must validate the path and extract the
key from its first certificate themselves. Certificate trust policy remains
with the caller.
