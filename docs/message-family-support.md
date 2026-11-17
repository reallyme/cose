# COSE message-family support

The public operation contract is defined in `cose.proto` and generated with
ReallyMe Buffa. Native typed requests, binary protobuf and ProtoJSON dispatch
through the same semantics. The operations below are available in the native
and WASM lanes. They do not perform reader protocol processing, certificate
trust policy, identity authorization or network key discovery.

| Standard clause | Generated operations | Independent and negative coverage |
| --- | --- | --- |
| RFC 9052 sections 4.1/4.4 | `sign_create`, `sign_verify` | RFC C.1.1/C.1.2; attached/detached content; every built-in suite; changed payload/AAD/signature/headers; indexed key/algorithm mismatch; critical/duplicate headers; bounds |
| RFC 9052 sections 5.2/5.3 | `encrypt0_create`, `encrypt0_decrypt` | COSE WG A128/192/256GCM bytes; attached/detached; IV and Partial IV; empty plaintext; changed ciphertext/AAD/tag/key; malformed headers; limits |
| RFC 9052 sections 6.1/6.3 | `mac_create`, `mac_verify` | COSE WG HMAC-01/02/03 and A128KW/HMAC-SHA512; truncated/detached MAC; changed content/AAD/tag/key/headers; malformed input; limits |
| RFC 9052 sections 8.5.1/8.5.2 and appendix B | MAC recipient creation and selected-path verification | Direct and all three AES-KW widths; multiple/nested recipients; independent wrapped-key vector; unsupported unselected recipient; wrong path/key; invalid mixed direct mode; depth cap |
| RFC 9052 section 7 | `key_set_parse`, `key_set_create` | RFC C.7.1 unsorted map; independent per-member outcomes; exact sensitive storage; public projection; duplicates, wrong shapes and bounds |
| RFC 9338 sections 2/3.1/3.3 | `counter_signature_create`, `counter_signature_verify` | All six RFC appendix A examples; all target kinds; standalone/tagged and embedded full collections; chaining; protected bytes, key, AAD and target tampering |
| RFC 9338 sections 2/3.2/3.3 | `counter_signature0_create`, `counter_signature0_verify` | Independently computed OpenSSL fixtures for both abbreviated contexts; exact preimages; no `sign_protected` placeholder; detached content; changed content/tag/AAD |
| RFC 9338 header 11/12 representation | `counter_signature_attach` | Exact primary-field preservation; primary AEAD still verifies; single/collection full counters; abbreviated replacement rejection; 32/33 boundary; deprecated 7/9 rejection |
| RFC 8230 section 2; RFC 8812 section 2 | `rsa_sign1_verify`; RSA suites in `sign_verify` and full/abbreviated counter verification | Independent OpenSSL SHA-256/384/512 PSS and PKCS#1 v1.5 signatures; exact protected bytes; wrong MGF1/salt, weak keys, payload/AAD/header/signature/key tampering; explicit suite allowlists and DER bounds |

The dedicated message-family entrypoints implement their own registered tags:
98 for Sign, 97 for Mac and 16 for Encrypt0. `limits/validate.rs` admits the
older primitive profiles; rejection of those tags by Sign1, detached Mac0 or
the private ML-KEM Encrypt API does not describe the general message APIs.
Their common framing lives in `messages/read_message.rs`. KeySet admission is
untagged, and RFC 9338 uses its explicit counter operations and headers 11/12.

All authenticated bytes are preserved. Sign, Signature1, MAC, MAC0, Encrypt,
Encrypt0 and the four counter contexts remain distinct. Algorithm identities
such as ES384/ESP384, ES512/ESP512 and EdDSA/Ed25519 are never substituted.
The existing explicit ISO/IEC 18013-5:2021 Sign1 profile is retained separately.
General-operation contracts define a definite preferred-CBOR profile, with
received map order retained.

Implementation versions are reallyme-cose/reallyme-cose-proto 0.3.0,
reallyme-crypto 0.4.2, reallyme-codec (including CBOR) 0.4.3 and ReallyMe Buffa
0.1.2; Rust/MSRV remains 1.100.0.

The focused tests run natively and in Node's WASM harness, including generated
transport parity. Deterministic creation is compared byte for byte. Random
wrapped-key MAC creation is authenticated independently through every transport.
This repository ships Rust/protobuf only; no mobile SDK or on-device validation
is claimed.

Crypto coverage remains explicitly bounded: built-in signature suites are
listed in the Sign contract, HMAC is the implemented MAC family, and Encrypt0
supports AES-GCM. Other registered algorithms need crypto/provider coverage;
they fail with fixed unsupported/provider reasons. Brainpool, Ed448 and X448
provider integration into these COSE message operations remains separate;
cryptographic implementation stays with reallyme-crypto. Generic KeySet parsing
is structural and does not replace mathematical key import or trust checks.
Multi-recipient COSE_Encrypt remains outside the existing private ML-KEM
profile. Existing Sign1/Mac0 profiles keep their own accepted header semantics.
RSA verification requires explicit selected registrations, curve UNSPECIFIED,
2048..8192-bit SPKI public keys and nonempty allowlists. RSA signing and OAEP
remain unavailable; no alternative crypto implementation or algorithm fallback
is installed. See [RSA verification](rsa-verification.md) for the exact contract.

See the [Sign](https://github.com/reallyme/cose/blob/main/docs/sign-message-contract.md),
[Encrypt0](https://github.com/reallyme/cose/blob/main/docs/encrypt0-contract.md),
[MAC](https://github.com/reallyme/cose/blob/main/docs/mac-message-contract.md),
[KeySet](https://github.com/reallyme/cose/blob/main/docs/key-set-contract.md) and
[countersignature](https://github.com/reallyme/cose/blob/main/docs/countersignature-contract.md)
contracts for exact resource ceilings and test names.
