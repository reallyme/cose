# Public agreement keys

`AgreementKey` provides public COSE_Key import and construction independently
of the signing APIs. It is available from `reallyme_cose::key` and
`reallyme_cose::containers` with either the `native` or `wasm` runtime lane.
The authoritative generated operations are `agreement_key_create` (2008) and
`agreement_key_parse` (2009), with `CoseAgreementKeyPolicy` and separate
`cose_key`/`public_key` result fields. The borrowed methods below are thin
adapters to these same semantic operations. This contract is part of unreleased 0.3.0; published 0.2.11 does not provide it.

The caller assigns reader/device roles and selects the negotiated curve and
encoding policy. COSE enforces that explicit selection. For ISO/IEC
18013-5:2021 9.1.5.2, use `FullCoordinatesOnly` for EReaderKey and
`FullOrCompressed` for EDeviceKey. The encoding restriction applies to the
received or emitted COSE_Key, before normalization. OKP keys always use their
registered public-byte form, independently of the EC2 policy.

```rust
use reallyme_cose::containers::{
    AgreementEc2EncodingPolicy, AgreementKey, AgreementKeyPolicy, ContainerError,
    CryptoAgreementKeyProvider, OptionalKeyPolicy, PeerCurve, PeerPointEncoding,
};

fn reader_public_key(public_sec1: &[u8]) -> Result<AgreementKey, ContainerError> {
    let curve = PeerCurve::P256;
    AgreementKey::from_public_key(
        curve,
        public_sec1,
        PeerPointEncoding::Ec2Coordinates,
        AgreementKeyPolicy {
            allowed_curves: &[curve],
            optional_parameters: OptionalKeyPolicy::IsoPeer,
            ec2_encoding: AgreementEc2EncodingPolicy::FullCoordinatesOnly,
        },
        &CryptoAgreementKeyProvider,
    )
}
```

`AgreementKey::from_slice` consumes an untagged COSE_Key map. It accepts
unsorted unique maps under the ISO preferred-encoding rules: definite lengths,
shortest encodings, bounded nesting/work and complete consumption. Its hard
input bound is `MAX_COSE_KEY_BYTES` (16,384 bytes), with at most 32 parameters.
Duplicates are rejected even in ignored optional fields. Private `d` and
unknown negative parameters are rejected before copying the input. The public
point is validated under its exact named curve and agreement purpose.

`OptionalKeyPolicy::Cose` accepts omitted `alg` and agreement `key_ops`
(`DeriveKey` 7 and/or `DeriveBits` 8). It rejects supplied `alg` because this
subset does not implement ECDH algorithm registrations, as well as signing
operations, duplicate operations and unknown optional fields.
`OptionalKeyPolicy::IsoPeer` explicitly ignores optional positive parameters,
including `alg`/`key_ops`, while preserving their exact encoded bytes. It never
relaxes required public parameters, duplicates, private-material exclusion,
curve allowlisting, or the selected EC2 encoding constraint. The existing
generic signing parser and constructors retain their separate behavior.

`from_public_key` accepts full or compressed SEC1 EC2 input, or canonical
Montgomery public bytes, and emits the selected representation. Its minimal,
deterministically ordered map contains only `kty`, `crv`, `x` and EC2 `y`.
It never invents a signing `alg` or `key_ops`. Full points are validated before
compression; invalid supplied y coordinates cannot be repaired by discarding y.

Each `AgreementKey` owns zeroizing buffers without formatting, cloning or
serialization implementations. `original_cose_key()` returns the exact received
map, or the constructed map. `public_material()` separately returns a validated
full SEC1 point (`04 || x || y`) or canonical Montgomery bytes. Normalization
cannot replace the supplied point identity. Never substitute normalized or
reconstructed bytes into a transcript. The format layer retains any surrounding
tag 24 / encoded-byte-string wrapper exactly; this boundary does not strip it.

`AgreementKeyProvider` owns mathematical validation and normalization.
`CryptoAgreementKeyProvider` uses only published `reallyme-crypto` 0.4.0 APIs
and executes P-256/P-384/P-521 and X25519 in native and WASM lanes. Registered
Brainpool and X448 mappings remain available to explicit crypto-owned provider
adapters; the built-in adapter returns `Provider`. Edwards keys are rejected
for agreement regardless of allowlisting. No curve is inferred from width or
silently substituted. Crypto provider implementation remains in `reallyme/crypto`.

All failures use the existing allocation-free `ContainerError` and fixed
`ContainerErrorReason`, without key bytes or diagnostic strings:

| Failure | Reason |
| --- | --- |
| Truncated, wrong CBOR shape, tagged map or trailing bytes | `Malformed` |
| Nonpreferred or indefinite encoding | `Encoding` |
| Duplicate map labels | `Duplicate` |
| Input, parser work, parameter count or allocation bound | `Limit` |
| Agreement-capable curve absent from explicit allowlist | `Algorithm` |
| Forbidden point representation under the selected policy | `Profile` |
| Private material, invalid point, wrong key family, restrictions or provider output | `Key` |
| Missing crypto capability | `Provider` |

| Clauses / requirement | API | Tests in `crates/cose/src/containers` |
| --- | --- | --- |
| ISO 2021 8.1; DIS 8.3: unique maps without required sorting | `from_slice`, exact `original_cose_key` | `agreement_tests.rs`: sorted/unsorted equivalence and original retention; `agreement_boundary_tests.rs`: duplicate/truncated/nonpreferred/trailing inputs |
| ISO 2021 9.1.5.2; DIS 12.7.2: agreement purpose, curves and EC2 forms | Explicit `AgreementKeyPolicy`, allowlist, point encoding; public-only construction | `agreement_tests.rs`: full/compressed policies, omitted alg, DeriveKey/DeriveBits, all eleven mappings including typed unsupported/Edwards failures |
| Separate public material and received bytes | Zeroizing `AgreementKey`, provider normalization and identity checks | Ownership, invalid y, malformed/substituted provider output and executable ECDH tests; provider callbacks excluded for invalid requests |
| Resource and deterministic-error boundary | Existing bounded parser and `ContainerErrorReason` | Maximum-size acceptance, over-limit failures and native allocation-free malformed/private rejection |

These tests reuse independently generated public-key fixtures in
`tests/fixtures/peer-keys.json`, including named NIST generators and separate
registered Brainpool/Ed448/X448 points. ECDH scalar-one answers independently
check the imported/constructed NIST points against their generator coordinates
through `reallyme-crypto`. Every agreement test executes in native and WASM
except the native allocation-counter test.

Session establishment, ECDH execution, KDF selection, negotiation, transcript
assembly, QR/NFC handover binding and trust policy remain caller responsibilities.
The new APIs include generated protobuf operations and add no platform SDK. Earlier signature,
certificate-container and Mac0 contracts remain tracked in their own documents.
