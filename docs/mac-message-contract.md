# COSE_Mac

`mac_create` and `mac_verify` implement RFC 9052 sections 6.1 and 6.3.
Their `MAC` authentication structure is distinct from `MAC0` and contains the
exact protected bytes, explicit AAD and attached or detached payload.
HMAC 256/64, 256/256, 384/384 and 512/512 require explicit allowlisting and
matching key/tag widths. Verification uses reallyme-crypto's constant-time MAC
boundary.

Recipients support direct shared keys and A128KW/A192KW/A256KW, including
nested groups. Wrapped MAC keys and intermediate KEKs are generated internally
and are not returned. Wrapped creation produces different bytes on each call.

A direct recipient must be the only recipient at its layer, with empty protected
bytes, an unprotected algorithm and an empty byte-string ciphertext. This is
distinct from the private ML-KEM profile's null ciphertext. AES-KW recipient
protected bytes must also be empty.

Verification selects a caller-authorized index path to a leaf key, enforces a
separate recipient-algorithm allowlist, unwraps that path and authenticates the
MAC before returning payload or metadata. An unsupported unselected recipient
does not block a supported path. Unprotected identifiers are discovery hints.

Limits are 32 recipients in total, four recipient layers, 32 labels and 16 KiB
per header bucket, 64 KiB AAD and 1 MiB per message/authentication structure.
Duplicate/conflicting headers, unsupported critical semantics, wrong content
mode, malformed widths and trailing data return fixed errors. AES-CBC-MAC,
ECDH/KDF and RSA transport are not supported.
