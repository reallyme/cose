# COSE_Encrypt0

The generated `encrypt0_create` and `encrypt0_decrypt` operations implement the
implicit-recipient structure in RFC 9052 sections 5.2 and 5.3. An explicit
allowlist and a key bound to A128GCM, A192GCM or A256GCM are required. The exact
protected bytes enter the `Encrypt0` Enc_structure; its context cannot be used
interchangeably with the existing `Encrypt` context.

Ciphertext can be attached or detached. A present detached-ciphertext field
requires a nil envelope slot. An attached byte string requires its absence.
Tags are the full 16-byte GCM tags. No plaintext or authenticated metadata is
returned until authentication succeeds. Raw key inputs are generated sensitive
owners and are consumed by reallyme-crypto's zeroizing AES key types.

Headers must contain either a full 12-byte IV or a nonempty Partial IV of at
most 12 bytes. Partial IV requires an explicit 12-byte Base IV. The nonce is
Base IV XOR the left-zero-padded Partial IV, as specified by RFC 9052 section
3.1. Both IV forms together, a missing base, or an irrelevant supplied base
are rejected. The caller owns nonce allocation and must never reuse a nonce
under the same key. This boundary does not maintain session counters.

The shared framing rejects duplicate/conflicting headers, unsupported critical
labels, malformed values, unexpected tags, indefinite/nonpreferred encodings,
and trailing data. Map order and protected bytes are retained. Limits are
1 MiB for the encoded message, 16 KiB and 32 labels per header bucket, and
64 KiB of external AAD. Codec checks the complete encoded output size before
allocation; crypto and ciphertext-copy scratch owners zeroize on failure.

| Requirement | Focused native/WASM test |
| --- | --- |
| Independent COSE WG AES-GCM vectors for all three key sizes | `encrypt0_independent_aes_gcm_vectors_match_creation_and_decryption` |
| Detached content, Partial IV, empty plaintext and clearing | `encrypt0_detached_partial_iv_empty_plaintext_and_ownership` |
| Ciphertext, nonce, tag, AAD, key and registration tampering | `encrypt0_tampered_content_aad_headers_nonce_tag_and_key_fail_closed` |
| Missing/conflicting IV, malformed headers, critical labels and bounds | `encrypt0_rejects_conflicting_malformed_iv_critical_and_resource_inputs` |

Independent data comes from the COSE working group's
[AES-GCM Encrypt0 examples](https://github.com/cose-wg/Examples/tree/master/aes-gcm-examples),
files `aes-gcm-enc-01.json`, `02.json` and `03.json`. The first ciphertext is
also used in [RFC 9338 appendix A.4.1](https://www.rfc-editor.org/rfc/rfc9338.html#appendix-A.4.1).
