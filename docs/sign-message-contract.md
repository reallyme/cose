# COSE_Sign

`sign_create` and `sign_verify` implement RFC 9052 sections 4.1 and 4.4, with
attached or explicit detached content, explicit AAD and a nonempty suite
allowlist. Verification requires an authorized indexed key for every signature
and verifies all signatures before returning a result. Threshold policy and
key discovery remain with the caller.

The `Signature` structure uses the exact body and signer protected byte strings.
An algorithm may be protected by the body or by an individual signer, but
cannot be repeated. Duplicate/conflicting headers, unprotected algorithms,
unsupported critical semantics and trailing data are rejected. Unprotected
identifiers are not authenticated signer identities.

Built-in suites include ES256/P-256, ES384/P-384, ES512/P-521, EdDSA/Ed25519,
the distinct ESP256/384/512 and Ed25519 registrations, ES256K and
ML-DSA-44/65/87. ML-DSA uses curve UNSPECIFIED. Recognized pairs without a
provider return a fixed provider-unavailable reason. No suite is implicitly
allowlisted.

Verification also supports the [RSA suites](rsa-verification.md). RSA creation
returns `PROVIDER_UNAVAILABLE`.

Limits are 32 signatures, 32 labels and 16 KiB per header bucket, 64 KiB AAD,
and 1 MiB per encoded message or authentication structure. Definite preferred
CBOR retains received map order.

P-256/P-384/P-521 verification accepts high-S ECDSA; secp256k1 requires low-S.
Do not deduplicate or detect replay by hashing COSE bytes. Use authenticated
message identity in the protocol context.
