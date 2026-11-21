# Signed containers

Use `verify_container` or `sign_container` with an explicit `ContainerPolicy`,
content mode, external AAD, suite allowlist and byte limits. Verification accepts
a validated key capability or `CertificateValidator`. Signing uses a
`ContainerSigner` and verifies its output before returning a signed container.
An empty allowlist permits nothing.

| Profile | Contract |
| --- | --- |
| `Iso2021` | ISO/IEC 18013-5:2021; untagged Sign1 and empty AAD |
| `IsoEdition2Dis` | Pinned edition-2 DIS draft; untagged Sign1 and empty AAD |
| `Rfc9360` | Generic strict certificate profile; explicit tagged/untagged policy and caller-supplied AAD |

`IsoEdition2Dis` implements a draft snapshot, not a final edition. Its source
SHA-256 is `8dc30c5a399ded7b4274c1aebb7624eeab02aaf8f55d0c225734b8aae140fb77`.
Select it explicitly; it does not change `Iso2021` acceptance.

## Content and certificates

| Purpose | Content | Certificate requirement |
| --- | --- | --- |
| `IssuerMso` | Attached CBOR | Chain required; ISO 2021 certificate resolution uses the unprotected bucket |
| `DeviceAuthentication` | Exact detached bytes | Validated key or certificate source |
| `ReaderAuthentication` | Exact detached bytes | Certificate resolution requires a chain; unprotected in ISO 2021 |
| `ReaderAuthenticationAll` | Exact detached bytes; draft profile only | Certificate resolution requires a chain |
| `MsoRevocation` | Attached CBOR; draft profile only | Protected chain |
| `Vical` | Attached CBOR | Unprotected chain |
| `Rical` | Attached CBOR; draft profile only | Protected chain |
| `Generic` | Explicit attached/detached content; RFC profile only | Protected chain or matching protected thumbprint when certificates are used |

Detached content requires the wire payload slot to be null. COSE does not build
ReaderAuthAll request ordering, transcript wrappers or authorization decisions.
Issuer payload preflight uses minimum argument widths for CBOR major types
0–5 in `Iso2021`; the draft profile also requires preferred tag and float widths.
Neither check establishes the full MSO or document schema.

`x5chain` is one certificate byte string or an array of at least two.
`CertificateValidator` receives discovery headers and the protected algorithm,
and returns a validated working key, its context identity and exact selected
end-entity DER. COSE requires that DER to equal `x5chain[0]` when a chain is
present, and requires the key suite to match the protected registration.
A protected SHA-256 `x5t` uses algorithm `-16` and exactly 32 digest bytes;
COSE compares it with SHA-256 of the selected DER.

A different certificate with the same public key is still a mismatch.
`CONTAINER_CERTIFICATE_MISMATCH` reports DER/thumbprint mismatch;
`KEY_ALGORITHM_MISMATCH` reports a mismatched key suite. Returned certificate
placement and integrity metadata do not establish path trust, issuer authority,
revocation freshness or application permission. Those remain validator/caller
responsibilities. The RFC profile does not infer certificate binding from
nonempty AAD. ISO profiles explicitly permit their unprotected-chain forms.

Native `OperationProviders::resolve_x5chain_key` receives placement and returns
`CoseProviderCertificateResult`, including the working key and selected DER.
Native Sign1 key-only certificate callbacks instead require the resolver to
validate the path and extract the first certificate's key itself.

## Algorithms and keys

ISO container profiles enforce these exact pairs:

| Registration | Permitted curves | Built-in support |
| --- | --- | --- |
| ES256 `-7` | P-256, brainpoolP256r1 | P-256 |
| ES384 `-35` | P-384, brainpoolP320r1, brainpoolP384r1 | P-384 |
| ES512 `-36` | P-521, brainpoolP512r1 | P-521 |
| EdDSA `-8` | Ed25519, Ed448 | Ed25519 |

The modern container profile uses ESP256 `-9`, ESP384 `-51`, ESP512 `-52`
and Ed25519 `-19` with their fully specified curves. Registrations are never
substituted. Brainpool, Ed448 and X448 mappings are recognized, but mathematical
validation/verification requires an additional crypto provider. Missing coverage
returns a fixed provider error.

`inspect_peer_key` preserves original COSE_Key bytes separately from public
material. Call `InspectedPeerKey::validate` before cryptographic use. Both
optional-parameter policies enforce public-only material, known field types,
exact signature `alg` and permitted `key_ops`. Signature keys may include
byte-string Base IV; it remains only in the original encoding.
`IsoPeer` additionally permits Base IV for agreement and unknown positive
parameters. Use the [agreement-key API](agreement-keys.md) for explicit
agreement construction and full-coordinate/compression policy.

## Bytes, limits and safety

Protected headers and supplied content are authenticated exactly as received.
Unsorted unique maps are accepted; duplicate/conflicting headers and unsupported
critical semantics are rejected. Unprotected headers remain unauthenticated.
Never reconstruct authenticated content from normalized points or decoded maps.

The default encoded budget is 65,536 bytes; explicit budgets can select up to
1,048,576 bytes. Payload, AAD, certificate and [CBOR limits](cbor-boundary.md)
remain independent. Receipts own wiping buffers; callers own input and detached
content. Signing providers must declare message/prehash mode and signature
encoding, and must bind verification to the same suite, public key and context.

P-256/P-384/P-521 verification accepts high-S ECDSA. Do not hash COSE bytes for
replay detection or deduplication; use authenticated protocol identity.
The APIs are available in native Rust and WASM. Rust mobile-target builds do
not supply Swift/Kotlin SDKs or device-provider integration.
