# Protobuf presence in 0.3.0

Regenerate consumers against the 0.3.0 schema and update producers and consumers
together. The package remains `reallyme.cose.v1`. This change affects protobuf
presence, not authenticated COSE encodings or algorithm registrations.

| Message | Value field | Retired flag number/name |
| --- | --- | --- |
| `CoseSign1CreateRequest` | `optional bytes kid = 4` | 5, `has_kid` |
| `CoseSign1CreateDetachedRequest` | `optional bytes kid = 4` | 5, `has_kid` |
| `CoseKeyFromPrivateBytesRequest` | `optional bytes public_key = 3` | 4, `has_public_key` |
| `CoseMlKemEncryptRequest` | `optional bytes supp_priv_info = 7` | 8, `has_supp_priv_info` |
| `CoseMlKemDecryptRequest` | `optional bytes supp_priv_info = 5` | 6, `has_supp_priv_info` |
| `CoseMac0VerifyResult` | `optional bytes protected_kid = 3` | 4, `has_protected_kid` |
| `CoseIsoSign1VerifyResult` | `optional bytes protected_kid = 3` | 4, `has_protected_kid` |
| `CoseIsoSign1VerifyResult` | `optional bytes attached_payload = 5` | 6, `has_attached_payload` |
| `CoseContainerVerifyResult` | `optional bytes certificate_sha256 = 10` | 11, `has_certificate_sha256` |
| `CoseSign1VerifyResult` | `exact_signature_algorithm = 4`; zero means absent | 5, `has_exact_signature_algorithm` |
| `CoseKeyBytesResult` | `signature_algorithm = 2`; zero means absent | 3, `has_signature_algorithm` |

Retired numbers and names are reserved. Executable adapters reject the old flags
in both binary protobuf and ProtoJSON.

Rust optional bytes are `Option<SecretBytes>`; borrowed views use
`Option<&[u8]>`. `None` omits the field. A present empty value writes its tag
and a zero length. ProtoJSON omits absent values, represents present-empty as
`""`, and treats `null` as absent. Supply only the value, without a `has_*` flag.

Signing rejects a present empty `kid`. Empty `SuppPrivInfo` is valid and differs
from absence. A verified empty attached payload is present; a detached receipt
omits it. A present certificate SHA-256 must contain exactly 32 bytes.

Nonempty byte values keep their field numbers and wire encodings. Empty values
are deliberately incompatible with the old implicit-presence fields: an old
sender's omitted empty value cannot be recovered from its retired flag. Do not
mix schema versions across producers and consumers. If decoding outside COSE's
executable adapters, reject unknown fields on the original bounded bytes;
default protobuf decoding can discard them.
