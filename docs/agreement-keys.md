# Public agreement keys

Use `AgreementKey` for public ECDH keys rather than a signing-key constructor.
It is exported from `reallyme_cose::key` and `reallyme_cose::containers` in the
`native` and `wasm` lanes. Protobuf operations are `agreement_key_create` and
`agreement_key_parse`.

The caller assigns reader/device roles. For ISO/IEC 18013-5:2021, select
`FullCoordinatesOnly` for EReaderKey and `FullOrCompressed` for EDeviceKey.
This policy applies to the received or emitted COSE_Key, before normalization.

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

`from_slice` accepts an untagged, definite-length COSE_Key map with unique labels
in any order. Limits are 16,384 bytes and 32 parameters. Nonpreferred encodings,
duplicates, private material, unknown negative labels and trailing bytes are
rejected. The curve allowlist and point-validation provider are required.

`OptionalKeyPolicy::Cose` permits omitted `alg` and agreement `key_ops`
(`DeriveKey` 7 and/or `DeriveBits` 8). Supplied `alg` is rejected because this
agreement subset has no ECDH algorithm registrations. Signing operations,
duplicate operations and unknown optional fields are rejected.
`IsoPeer` additionally permits byte-string Base IV and unknown positive
parameters, retaining their bytes. It still checks known parameter types,
algorithm/operation restrictions and public-only material.

`from_public_key` accepts full or compressed SEC1 EC2 input or canonical
Montgomery bytes. It validates the point and emits only `kty`, `crv`, `x` and
EC2 `y`, without a signing algorithm or invented key operations.

`original_cose_key()` borrows the exact received or constructed map.
`public_material()` borrows a separately validated full SEC1 point or canonical
Montgomery bytes. Both are owned by wiping buffers. Use the original encoding
for transcripts; retain any surrounding tag-24 wrapper in the format layer.

The built-in `CryptoAgreementKeyProvider` supports P-256/P-384/P-521 and X25519.
Brainpool and X448 require a crypto-owned `AgreementKeyProvider`; without one,
import returns the fixed provider error. Edwards keys cannot be agreement keys.
Session establishment, ECDH execution, KDF selection, negotiation and transcript
construction remain caller responsibilities.
