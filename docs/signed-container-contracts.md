# Signed-container contracts for ISO readers

The `containers` module adds explicit COSE contracts for ISO 2021, the pinned
edition-2 DIS snapshot, and a strict RFC 9360 subset. These additions are
unreleased changes in the working `reallyme-cose` 0.2.11 tree. The earlier
[ISO signature-registration work](iso18013-signature-profile.md) and detached
Mac0 primitive remain separate APIs and separate acceptance evidence.

## Source baselines

The licensed ISO sources were reviewed in place; their text and CDDL are not
redistributed here. The baselines are:

| Source | SHA-256 |
| --- | --- |
| ISO/IEC 18013-5:2021 | `bfb9bf437656c628f2c201a35fc4873abf41d7f0314ae410d1f1b437a8e8fc5e` |
| ISO/IEC DIS 18013-5, edition-2 snapshot | `8dc30c5a399ded7b4274c1aebb7624eeab02aaf8f55d0c225734b8aae140fb77` |

The DIS cover identifies 2026 while its main text identifies 2025. It is a draft
snapshot, not a final publication or a claim about the latest available text.
Its ReaderAuthAll comments/prose contain inconsistent names; the API therefore
accepts exact caller-built bytes and records a distinct purpose without encoding
those names. Its informative Brainpool assignment discussion predates the
registered identifiers. The current
[IANA curve registry](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves)
was checked on 2026-11-12: Brainpool r1 curves use 256–259, X448 uses 5, and
Ed448 uses 7. The latter two have different operations and public-key widths.

Public references are [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html),
[RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html),
[RFC 9360](https://www.rfc-editor.org/rfc/rfc9360.html), and
[RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1).
Named ECDSA subgroup orders used by signature conversion come from SEC 2 and
[RFC 5639](https://www.rfc-editor.org/rfc/rfc5639.html).

## Explicit verification contract

`verify_container(ContainerVerifyRequest, VerificationSource)` requires the
profile, purpose, envelope policy, attached/detached content, explicit external
AAD, exact suite allowlist, resource limits, and a validated key capability or
certificate-validation boundary. An empty allowlist permits nothing. ISO
containers require untagged envelopes and empty AAD. Generic RFC 9360 callers
choose untagged, tagged, or either explicitly and supply their own AAD.

The parser borrows validated spans instead of allocating CBOR trees. Protected
header bytes are placed unchanged in Sig_structure. Unsorted maps are accepted;
duplicate labels, including semantic duplicate compound map keys, are rejected.
Unknown noncritical headers remain accessible in exact protected/unprotected
spans; unsupported critical semantics fail closed. Successful receipts own and
wipe envelope, headers, payload, actual public key, certificate digest and
verification context. They implement no formatting, cloning or serialization.
Unprotected header bytes remain explicitly unauthenticated. Known content-type
text is checked using the shared bare RFC 6838 media-type validator; malformed
values fail before certificate resolution or signing.

COSE-owned profile, attachment, certificate-placement and permitted signature-format
checks run before certificate resolution. Creation checks the exact encoded result
size and declared signer input/encoding contract before signing, and reserves the
output fallibly before invoking a key capability. The built-in verifier retains
one zeroizing public-key owner. Regression tests assert that invalid requests do
not invoke provider callbacks.

`CertificateValidator` receives untrusted discovery headers and the exact
protected algorithm. It returns the effective validated working key/parameters
and exact selected end-entity DER. COSE checks the supplied chain leaf against
that selected DER and checks protected x5t against SHA-256 of those exact bytes
using `reallyme-crypto` constant-time equality. SHA-256 is registration `-16`
and exactly 32 bytes. The receipt binds the actual public key, context ID,
selected-certificate digest, chain placement and integrity rule.

The strict RFC 9360 subset requires a protected chain or matching protected
thumbprint when certificates are used. It does not infer certificate integrity
from nonempty AAD; protocol-specific certificate binding through AAD is not
implemented. ISO compatibility explicitly permits the unprotected-chain
exception. A certificate/thumbprint match never grants path trust, issuer
authority, schema acceptance or revocation freshness. Generic mdoc and mDL
Annex B certificate policies belong in separate injected validators.

## Clause-to-API and test matrix

All APIs below require one runtime lane: `native` or `wasm`. They need neither
protobuf `wire` nor sibling repository changes. Paths in this table are relative
to `crates/cose/src/containers` unless stated otherwise.

| Requirement / clauses | API and enforced contract | Execution evidence |
| --- | --- | --- |
| CO-DIS-01; DIS 12.3.4, 12.5.4; RFC 9360 | `CertificateHeaders`, `CertificateValidator`, `HeaderProvenance`; bstr single certificate or array of at least two; protected SHA-256 x5t; exact selected DER and effective key | `header_tests.rs`, `verify_tests.rs`: both chain buckets, malformed/unsupported/wrong x5t, duplicate/critical headers, certificate substitution with the same public key |
| DIS 12.8.1; 2021 trust boundary | `CertificateSelection`, `VerificationKey`, receipt public-key/context/certificate digest accessors | Independent verification under the actual capability; wrong key, wrong registration and substituted DER rejected; certificate-path rules remain external |
| CO-DIS-02; DIS 12.3.4; 2021 issuer signatures | `IssuerMso` with attached opaque CBOR bytes, preserving original tag 24 | `containers.json` issuer cases and `independent_container_answers_preserve_exact_bytes_and_key_binding` |
| DIS 12.4.4/12.4.6 | `DeviceAuthentication`, explicit `ContainerContent::Detached` and null wire payload | `verify_tests.rs`, `suite_tests.rs`: independent signatures, changed payload, attached/detached confusion |
| DIS 12.5.4, 9.1, 10.2.6 | Separate `ReaderAuthentication` / `ReaderAuthenticationAll`; exact supplied bytes, empty AAD | Distinct independent single/all cases; ordered request bytes and optional/null values preserved. Negotiation/authorization are reader policy |
| DIS 12.3.6.3 | `MsoRevocation`: attached CBOR and protected x5chain required | Independent signed revocation case; wrong placement/container rejected |
| Annex C.1.7.1 | `Vical`: attached CBOR, unprotected chain, empty AAD | Independent signed VICAL case; protected-chain substitution rejected by contract |
| Informative Annex F.3.2 | `Rical`: attached CBOR, protected chain, empty AAD; explicit opt-in | Independent signed RICAL case; unprotected-chain substitution rejected by contract |
| CO-DIS-03; DIS 12.3.4/12.4.6; RFC 8152 registrations | `SignatureSuite::iso` enforces the ISO algorithm/curve pairs; `SignatureSuite::modern` keeps fully specified IDs distinct | `signature-suites.json` has thirteen independently signed cases; `suite_tests.rs` executes supported pairs and rejects registration substitution; absent providers return `Provider` |
| DIS 12.7.2 table 17; 2021 table 22 | `PeerCurve`, `inspect_peer_key`, `InspectedPeerKey::validate`; all eleven registered mappings; original COSE_Key and point encoding retained | `peer-keys.json`, `peer_tests.rs`: exact IDs/widths/kty/usage, full/compressed points, private/unknown negative parameters rejected before copying, typed provider gaps |
| DIS optional peer parameters | `OptionalKeyPolicy::Cose` enforces alg/key_ops; `IsoPeer` ignores optional positive parameters while retaining required shape and excluding private d | `optional_parameter_policy_private_material_and_usage_mismatches_are_explicit` |
| DIS 12.6 raw HPKE boundary | `PeerKeyUsage::Agreement` / `HpkeRecipient`, validated named-curve public material independent of a signing registration | P-256 recipient import and point validation execute without alg. HPKE, KEM selection, enc/cipherText and transcript construction are outside COSE |
| CO-DIS-04; DIS 8.3; RFC 8949 §4.2.1 | `validate_preferred_cbor`: definite lengths, shortest integer/length/tag/float widths, UTF-8, duplicate checks; sorting not required | `encoding_tests.rs`: tags, half/single/double values, NaNs, signed zero, unsorted and compound-key maps, malformed/trailing/deep/oversized input |
| CO-DIS-04 ownership and resource boundaries | Borrowed parsing; zeroizing final/temporary owners; fallible new-path allocations; fixed `ContainerErrorReason`; checked offsets/capacities | Allocation-free malformed-input test, zeroizing-owner assertions, maximum detached payload, tightened limits, certificate and truncation tests, `boundary_tests.rs` provider-call and allocation checks; `cose_containers` fuzz target |
| CO-DIS-05; RFC 9052 Sig_structure | `ContainerSigner`, `sign_container`, finalized exact headers; validated public capability, independent output verification | Non-exporting ECDSA and pure EdDSA test providers; deterministic independent EdDSA answer, message/prehash modes, wrong public key, backend failure, changed finalized content, explicit AAD and double-hash rejection |
| CO-DIS-05; RFC 9053 §2.1 | Declared `SignatureEncoding`; shared strict DER/fixed-width conversion; scalar bounds, P-521 66-byte and Brainpool P320 40-byte components; Ed448 114-byte signature | `encoding_tests.rs` covers all seven ECDSA curves, high-S acceptance, zero/order scalars, negative/nonminimal/trailing DER and DER/raw/family confusion; independent conversion cases in `peer-keys.json` |

This encoding preflight validates CBOR, not the complete ISO message grammar.
Encoded byte-string contents remain opaque: the format layer must validate the
MSO/document schema and any embedded CBOR at the appropriate boundary. ZKP
payload negotiation and proof semantics are not ordinary Sign1 semantics.

## Algorithms, providers and actual coverage

The ISO contract permits only these nine pairs:

| Registration | Permitted signature curves | Built-in execution in native and WASM |
| --- | --- | --- |
| ES256 `-7` | P-256; brainpoolP256r1 | P-256 |
| ES384 `-35` | P-384; brainpoolP320r1; brainpoolP384r1 | P-384 |
| ES512 `-36` | P-521; brainpoolP512r1 | P-521 |
| EdDSA `-8` | Ed25519; Ed448 | Ed25519 |

The modern strict container subset executes ESP256 `-9`, ESP384 `-51`, ESP512
`-52` and Ed25519 `-19`, each with its fully specified curve. These IDs are never
substituted for ISO registrations. Existing modern APIs/defaults are unchanged.
The earlier `iso18013` API resolves signature families and leaves individual
pair authorization to its caller; this new container contract additionally
checks the ISO pair table.

Public point validation executes for P-256/P-384/P-521, Ed25519 and X25519.
Agreement/HPKE usage excludes Edwards keys; signatures exclude X25519/X448.
Brainpool, Ed448 and X448 inspection is tested, but validated import and built-in
signature verification fail closed with `ContainerErrorReason::Provider` where
the pinned published facade lacks coverage. Enum/width recognition is not
execution evidence. The independently generated unavailable-curve fixtures do
not establish an integrated provider.

Crypto work remains in `reallyme/crypto`: named Brainpool point/subgroup
validation and the four required ECDSA pairs, pure Ed448 validation/sign/verify,
and X448 public validation/agreement through the published facade. Platform
signers need message-versus-prehash and declared DER/raw adapters implementing
these contracts. No platform private key is imported into COSE. The application
must implement certificate validation and bind its stable context identity.

## Versions and feature recipes

| Package | Exact resolved version |
| --- | --- |
| reallyme-cose | 0.2.11 (working tree additions, unpublished) |
| reallyme-cose-proto | 0.2.11 (schema unchanged) |
| reallyme-crypto | 0.3.17 |
| reallyme-codec | 0.3.2 |
| half (CBOR float-width checks only) | 2.7.1 |

Production cryptography, hashing and constant-time equality are imported solely
through `reallyme-crypto`. Independent crypto dependencies appear only in tests.

```toml
# Native Rust, including iOS/Android adapters:
reallyme-cose = { version = "0.2.11", default-features = false, features = ["native"] }
# wasm32-unknown-unknown instead uses features = ["wasm"].
```

These recipes describe this checkout. Published 0.2.11 does not contain the
unreleased additions; registry consumers need a subsequent release.

These are the minimal current feature recipes, not new narrow primitive
features. Their dependency breadth does not establish provider or reader
operation coverage. `wire` remains optional; these Rust-only contracts do not
add protobuf operations or mobile SDK packages.

## Validation and remaining integration

The acceptance commands are the repository release-readiness gate, native
container tests, WASM unit tests through Node, and `cargo check` plus strict
`cargo clippy --workspace --all-targets` with `--no-default-features --features
native` for each installed mobile target:

- `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`;
- `aarch64-linux-android`, `armv7-linux-androideabi`, `i686-linux-android`,
  `x86_64-linux-android`.

Android cross checks use the installed NDK compiler and archiver through the
per-target `CC_<target_with_underscores>` and `AR_<target_with_underscores>`
variables (API 24). These are compile/lint checks, not execution on devices.
Native/WASM execution and exact final counts are reported with the change.

Measured acceptance evidence for this checkout:

| Lane/check | Result |
| --- | --- |
| New container tests, native | 29 tests passed |
| New container tests, WASM/Node | 27 tests passed (two allocation-counter tests are native-only) |
| Complete WASM unit suite | 45 tests passed, including the separate earlier ISO tests |
| Native nextest lane | 297 tests passed |
| All-features release nextest | 380 tests passed |
| All-features debug tests including doctests | 382 tests passed |
| Seven installed iOS/Android targets | All-target compile and strict Clippy passed |
| Seeded bounded container fuzz smoke | 18,540 executions in 21 seconds; no crash |
| Release-readiness, vector audit, dependency/advisory policy | Passed |

Remaining reader work includes role-specific EReaderKey/EDeviceKey compressed
point policy, ordered ReaderAuthAll content construction and permission,
certificate path/authority policy, CWT/status-list/VICAL/RICAL schemas and
freshness, HPKE integration, response-status/document rules, complete ISO format
preflight, and ZKP contracts. None of those are accepted merely by obtaining a
COSE receipt. Platform Secure Enclave/Keystore handles have contract tests, not
on-device integration evidence. There is no remote publication in this work.
