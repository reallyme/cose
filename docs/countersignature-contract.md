# RFC 9338 countersignatures

Use `counter_signature_create` / `counter_signature_verify` for full V2
countersignatures, `counter_signature0_create` / `counter_signature0_verify`
for abbreviated V2 countersignatures, and `counter_signature_attach` to attach
a counter without verifying it. Supply the target kind, exact envelope bytes,
envelope policy, any detached content, algorithms, keys and allowlists.

Full counters contain protected headers, unprotected headers and a signature.
They may be standalone (optionally tagged 19) or indexed in unprotected header
11. Abbreviated counters are byte strings, standalone or in header 12, with
caller-supplied algorithm/key context. Deprecated headers 7/9 are rejected.
The key index must match a selected full counter; use zero for standalone or
abbreviated counters.

| Target | Full context | Abbreviated context | Additional field |
| --- | --- | --- | --- |
| Sign, Signature, Encrypt, Encrypt0, Recipient, full counter | `CounterSignature` | `CounterSignature0` | None |
| Sign1 | `CounterSignatureV2` | `CounterSignature0V2` | Primary signature |
| Mac, Mac0 | `CounterSignatureV2` | `CounterSignature0V2` | Primary tag |

COSE extracts these fields from the target. Abbreviated structures omit
`sign_protected`; an empty placeholder is invalid. Protected bytes retain their
exact encoding. Detached content requires a null slot.

Attachment preserves other primary fields byte for byte. It can append full
counters, but cannot replace an existing abbreviated counter. Attachment does
not authenticate the target or counter; verify separately.

Counter verification authenticates the extracted target bytes. It does not
verify the primary signature/MAC/AEAD, authorize its signer or establish trust.
The primary operation remains responsible for its critical headers. Short
primary MAC/AEAD tags limit counter collision strength, as described in
RFC 9338 section 6.

Limits are 1 MiB per message/authentication structure, 64 KiB counter AAD,
16 KiB and 32 labels per header bucket, 32 full counters per header and shared
CBOR nesting/work bounds. Signature support follows [Sign](sign-message-contract.md),
including [RSA verification](rsa-verification.md). RSA creation is unavailable.
P-256/P-384/P-521 accepts high-S ECDSA; do not deduplicate or detect replay by
hashing COSE bytes.
