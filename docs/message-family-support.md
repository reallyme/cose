# COSE message support

Operations are available through generated Rust requests, binary protobuf and
ProtoJSON in the native and WASM lanes. Each operation requires explicit policy;
acceptance by one profile does not authorize another.

| Format | Operations | Contract |
| --- | --- | --- |
| Sign1 | `sign1_create`, `sign1_create_detached`, `sign1_verify`, `sign1_verify_detached` and profile variants | [Key binding](sign1-key-binding.md) |
| ISO Sign1 | `iso_sign1_verify` | [ISO 2021](iso18013-signature-profile.md) |
| Certificate Sign1 | `container_sign`, `container_verify` | [Signed containers](signed-container-contracts.md) |
| Sign, tag 98 | `sign_create`, `sign_verify` | [Sign](sign-message-contract.md) |
| Mac, tag 97 | `mac_create`, `mac_verify` | [MAC and recipients](mac-message-contract.md) |
| Mac0 | `mac0_verify_detached` | Detached content and explicit HMAC registration |
| Encrypt0, tag 16 | `encrypt0_create`, `encrypt0_decrypt` | [Encrypt0](encrypt0-contract.md) |
| Encrypt | `ml_kem_encrypt_direct`, `ml_kem_encrypt_key_wrap`, `ml_kem_decrypt` | Private single-recipient ML-KEM profile; [context limit](encryption-context-limits.md) |
| KeySet | `key_set_parse`, `key_set_create` | [KeySet](key-set-contract.md) |
| Countersignatures | Full/abbreviated V2 create/verify and attachment | [RFC 9338 counters](countersignature-contract.md) |
| RSA | `rsa_sign1_verify`; RSA suites in Sign and counter verification | [RSA verification](rsa-verification.md) |

Authenticated protected bytes retain their received encoding. Contexts such as
`Signature`, `Signature1`, `MAC`, `MAC0`, `Encrypt` and `Encrypt0` are distinct.
ES384/ESP384, ES512/ESP512 and EdDSA/Ed25519 are distinct registrations.
General message operations use definite preferred CBOR without sorting received
maps. Older Sign1/Mac0/private-Encrypt profiles retain their own header rules.

Supported primitives are limited to the algorithms listed in each contract.
Unavailable algorithms/providers return fixed errors. Brainpool, Ed448 and X448
mappings do not imply built-in provider coverage. RSA signing/OAEP and generic
multi-recipient Encrypt are unavailable. KeySet parsing is structural, not
mathematical key validation.

Certificate trust, identity authorization, reader protocols and network key
discovery remain caller responsibilities. This repository ships Rust and
protobuf crates, not mobile SDKs.
