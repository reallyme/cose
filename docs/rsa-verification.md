# RSA verification

| Registration | COSE ID | Verification parameters |
| --- | --- | --- |
| PS256 | -37 | SHA-256, MGF1 SHA-256, 32-byte salt |
| PS384 | -38 | SHA-384, MGF1 SHA-384, 48-byte salt |
| PS512 | -39 | SHA-512, MGF1 SHA-512, 64-byte salt |
| RS256 | -257 | PKCS#1 v1.5, SHA-256 |
| RS384 | -258 | PKCS#1 v1.5, SHA-384 |
| RS512 | -259 | PKCS#1 v1.5, SHA-512 |

`rsa_sign1_verify` accepts attached or explicit detached Sign1 content,
external AAD, an exact suite/key binding, a nonempty unique suite allowlist and
optional expected protected `kid`. Set `signature_index` to zero. A present
detached payload, including an empty one, requires a null wire payload slot.
An absent detached payload requires an attached byte string.

`sign_verify` and full/abbreviated counter verification accept the same RSA
suites through their indexed-key bindings. Use curve UNSPECIFIED. Public keys
must be DER `rsaEncryption` SubjectPublicKeyInfo with 2048–8192 modulus bits.
PKCS#1 key blobs, certificates, private keys and automatic format detection are
not accepted. Signature length must equal the modulus width. Padding, salt,
MGF1 and hash parameters are fixed by the selected registration; SHA-1 is not
supported.

Authorize the exact registration and key identity together. Unprotected headers
do not establish trust. Protected bytes retain their received encoding, including
unsorted map order. A successful result includes the suite, protected bytes,
protected `kid` and attached payload; detached content remains caller-owned.

Limits are 1 MiB per message/content/authentication structure, 16 KiB and
32 labels per header bucket, 64 KiB AAD and 32 allowlisted suites. Shared CBOR
limits apply. Duplicate/conflicting headers, unsupported critical semantics,
malformed keys and invalid signatures return fixed protobuf reasons.

RSA signing and OAEP are unavailable. Creation with an RSA suite returns
`PROVIDER_UNAVAILABLE`. KeySet RSA storage/public projection does not establish
mathematical key validity. Certificate-path and reader policy remain external.
