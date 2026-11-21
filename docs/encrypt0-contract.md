# COSE_Encrypt0

`encrypt0_create` and `encrypt0_decrypt` implement RFC 9052 sections 5.2 and 5.3.
Supply an explicit algorithm allowlist and a key bound to A128GCM, A192GCM or
A256GCM. `Encrypt0` and `Encrypt` authentication contexts are distinct.

Ciphertext may be attached or detached. A present detached-ciphertext field
requires a null envelope slot; an attached byte string requires that field to
be absent. GCM tags are 16 bytes. Plaintext and authenticated metadata are
returned only after authentication succeeds.

Supply either a full 12-byte IV or a nonempty Partial IV of at most 12 bytes.
Partial IV requires an explicit 12-byte Base IV; the nonce is Base IV XOR the
left-zero-padded Partial IV. Both IV forms together, a missing base or an
irrelevant supplied base are rejected. The caller must allocate nonces and
never reuse one under the same key; COSE maintains no session counter.

The profile requires definite preferred CBOR and retains received map order and
protected bytes. Duplicate/conflicting headers, unsupported critical semantics,
malformed values, unexpected tags and trailing data are rejected.
Limits are 1 MiB encoded input, 16 KiB and 32 labels per header bucket, and
64 KiB AAD. Caller-owned keys, input and serialized copies require their own
sensitive-buffer ownership.
