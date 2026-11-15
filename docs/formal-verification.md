# Formal verification

The 0.4.0 verification work focuses on how COSE selects algorithms and keys,
constructs authenticated byte sequences, and gates successful results on
cryptographic checks. Kani checks the actual Rust functions with symbolic
inputs. The existing interoperability vectors and fuzz targets cover larger
inputs, real cryptographic providers, and the byte-entry points.

## Proofs in CI

| Area | Obligation | Scope |
| --- | --- | --- |
| Signature registration | Each supported numeric wire ID selects its exact registration and primitive. Legacy curve-dependent, unknown, and private-use IDs fail modern selection. | All `i64` values, against an independent IANA registration table. |
| Sign1 policy | Restricted policies admit exactly the registrations in the active allowlist. ES256 and ESP256 cannot authorize each other at any position. | Every generated registration against all ordered lists of zero to 32 raw protobuf selector values, including duplicates, unknown values, and deprecated selectors for fully specified ECDSA. A separate proof places an exact or sibling P-256 registration at any active position. Native regressions exercise all 32 positions in attached and detached verification. |
| Sign1 header placement | Unprotected `alg`, `kid`, and COSE type are rejected. Critical fields in either bucket fail closed. | All combinations of the five field-presence flags in a parsed Sign1 fixture. The protected algorithm is present in every case. |
| Sign1 authenticated bytes | The verifier's input builder preserves the original protected bstr, external AAD, and payload, in order and with the `Signature1` context. It rejects a missing original bstr. | The small-input proof uses an out-of-order protected map and symbolic `kid`, AAD, and payload bytes. At 23, 24, 255, and 256 bytes, separate proofs check the exact prefix, output length, and every byte of an arbitrary input to the production byte-string encoder. A builder proof observes the original slices and their lengths at the append boundary for every combination. A native regression compares the complete encoding to an independent encoder for all 64 combinations. |
| Sign1 boundary-sized backend input | Both attached and detached verification pass the received protected bstr, external AAD, and intended payload to the builder. Crypto dispatch receives the builder's original buffer, full length, and exact byte at every offset. | Kani covers all 64 combinations of the three field lengths using a modeled builder output with arbitrary contents and checking an arbitrary offset. It models wire decoding, protected-byte preflight, policy, signature conversion, and fixture wiping, with an observation at crypto dispatch. A native regression signs an independently encoded structure for each combination, verifies both wire forms through the production decoder and Ed25519 backend, and checks that changing any one of the three fields invalidates the signature. |
| Sign1 authentication gate | Attached and detached verification enforce payload placement before resolving the protected algorithm and `kid`. The verification flow passes the received protected bytes, AAD and intended payload to the structure builder, then forwards the builder output, resolved key and signature to the backend. Only backend acceptance releases authenticated metadata and, for attached verification, the payload. | An Ed25519 fixture with symbolic embedded-payload presence and backend acceptance. Stubs model wire decoding, protected-byte preflight, policy, the structure builder, signature conversion, fixture wiping and cryptographic verification. |
| Sign1 P-256 dispatch | The shared attached and detached verifier resolves the original ES256 or ESP256 registration with the protected `kid`. Each registration reaches the P-256 backend with its own resolved key. An unresolved key, `kid` mismatch, or algorithm mismatch returns its typed reason before structure construction, signature conversion, or backend verification. | Decoded fixtures with one protected `kid` and distinct resolver results for ES256 and ESP256. The proofs exercise production algorithm selection and resolver handling. They model protected-byte preflight, default policy, structure building, signature conversion, and cryptographic verification. Recursive cleanup of the public fixtures is outside the model. |
| Sign1 `x5chain` trust gate | Missing placement, an empty chain, and an unprotected chain without opt-in are rejected before trust resolution. For a permitted placement, the trust resolver receives the exact algorithm and decoded chain. A rejected lookup returns `KeyNotResolved` before structure building, signature conversion, or backend verification. | A borrowed, decoded Ed25519 fixture with symbolic placement, chain presence, and unprotected opt-in. The placement check and resolver handling run in production code. The harness models protected-byte preflight, general Sign1 policy, structure building, signature conversion, and cryptographic verification. Wire decoding and cleanup of the synthetic fixture are outside the model. The native regression covers both accepted and rejected trust lookups for each permitted placement. |
| Sign1 `x5chain` wire placement | Label 33 in either header bucket yields that placement. Label 33 in both buckets returns `DuplicateMapLabel` before trust resolution, even with unprotected placement enabled. | Kani checks the production label and placement logic for every pair of decoded integer labels. A separate harness checks that the public verifier propagates the duplicate decoder error for tagged and untagged fixtures. Native tests join both checks through the production CBOR reader. |
| Tagged Sign1 `x5chain` order | The tag-18 envelope preserves the Sign1 field positions and sets the tag flag. A certificate array reaches the trust resolver in encoded order when its placement is permitted. | The envelope proof covers parsed tag numbers and three- and four-field arrays. A separate proof checks the traversal used by production validation and copying for two or three symbolic two-byte certificates. The resolver adapter proof covers both array lengths in either placement and models the shared signature verifier at its resolver boundary. Native tests compose the production CBOR reader, chain copying, tag policy, and resolver for two- and three-certificate arrays. They also cover a required tag that is absent, an unexpected tag, duplicate placement, and a malformed array. |
| Sign1 `x5chain` array limits | An array must have at least two entries and stay within the configured certificate-count, per-certificate, and aggregate-byte limits. Entries must be nonempty byte strings. Malformed or oversized arrays stop before trust resolution. | Kani checks all machine-sized counts and individual lengths, plus every permitted count with symbolic 16-bit lengths and non-byte-string entries for the aggregate check. A parsed-array proof checks that a malformed late entry never reaches the copy stage. A verifier proof models the decoder's two typed errors. Native tests connect the proofs through tagged CBOR in both header buckets and set the outer Sign1 ceiling to include each fixture's framing bytes. |
| P-256 public extraction | The extractor returns exactly the compressed SEC1 prefix and the supplied X coordinate. The private scalar `d` cannot affect those bytes or substitute for missing `x` or `y`. Full-coordinate extraction returns a point only after provider acceptance. | Bounded parameter slices with symbolic 32-byte X, Y, and `d` and symbolic compact Y sign. The production label lookup and projection run for compact and full-coordinate inputs. Full-point validation is modeled as acceptance or typed rejection. The model omits recursive cleanup for the synthetic CBOR fixtures. |
| P-256 `kid` hash input | The fixed-size public encoder passes only `kty`, `alg`, `crv`, `x`, and the Y sign to SHA-256, preserving ES256 (`-7`) and ESP256 (`-9`) exactly. An unsupported registration or invalid compressed-point prefix cannot reach the hash. | All 32 X bytes and both Y signs at the production hash boundary. The encoder takes a compressed public point and an exact registration, and has no private-key input. The harness observes the input to SHA-256 through a stub. |
| Ed25519 `kid` hash input | SHA-256 receives exactly the 42-byte canonical map with `kty` OKP, `alg` Ed25519 (`-19`), `crv` Ed25519 (`6`), and the 32-byte `x`. The seed `d` cannot change those bytes or stand in for a missing `x`. | Kani exercises the production projection and encoder with independent symbolic `x` and `d` bytes, optional `d`, and explicit or omitted `alg`. It observes the exact prefix, length, and an arbitrary public-key byte at the SHA-256 boundary. The native RFC 8032 vector exercises the full derivation path, including profile and private/public pair validation. |
| OKP and EC2 key defaults | The curve selects the exact default registration and coordinate width. X25519 stays without a signature registration. Unknown curves fail closed. | All `i64` curve IDs. A native regression checks each EC2 family against the identifier derived from the corresponding canonical public key. |
| AKP public projection | AKP extraction selects the public parameter and enforces its expected length. The private parameter cannot replace the public bytes. ML-DSA and ML-KEM profiles bind the exact algorithm and material widths. | Symbolic bytes in a bounded two-parameter fixture and all machine-sized expected lengths. Registration checks cover the supported ML-DSA algorithms, all private-use IDs, and a mismatched assigned algorithm. Native ML-KEM vectors check projection and digest at the actual key widths. |
| Authentication lengths | CBOR byte-string sizing accounts for the correct prefix width and fails on overflow. | Every pair of 64-bit `usize` inputs to the size helper. |
| CBOR admission and limits | The outer length gate runs before parsing and accepts only complete items. Depth, collection count, and the COSE role constrain parsing work. | All depth and collection counts, all COSE container roles, and a small input at an arbitrary outer ceiling with a modeled parser. Native tests exercise the real reader at the nesting and collection limits. |
| Mac0 authentication | The exact protected HMAC registration and tag length gate MAC verification. The backend receives the original protected bytes, external AAD, and detached payload in `MAC0` context. Only backend acceptance releases protected metadata. | All numeric wire IDs and both SHA-256 registration directions. The length proof covers all machine-sized tag lengths with a single-entry or empty allowlist. The handoff model uses a symbolic one-byte AAD and payload, a decoded HMAC 256/64 fixture, and a modeled structure serializer and verifier. The header proof models placement and field validation and checks that metadata uses only the protected `kid`. Native duplicate-header tests exercise placement. Native tests exercise all four HMAC registrations. |
| ECDSA signature representation | DER lengths use their minimal supported form. DER scalar contents must be positive and minimally encoded. NIST curve dispatch enforces the exact raw COSE width. | All short and one-byte extended DER length heads and one- and two-byte scalar contents. The raw-width proof covers all three supported NIST widths against signatures of up to 133 bytes. Native tests exercise full DER conversion, positive sign padding, and the P-521 long-form sequence. |
| ML-KEM recipient registration | Each private-use ID selects the documented mode, parameter set, wire lengths, and optional AES-KW registration and key length. Unknown private-use IDs fail closed. | All `i64` values supplied as private-use labels. |
| ML-KEM KDF context | The context is `[AlgorithmID, [keyDataLength, protected], ?SuppPrivInfo]`. It retains the exact algorithm, checked output length in bits, both byte strings, and the distinction between absent and empty private information. | Kani checks the production context builder for all `i64` algorithm IDs and machine-sized output lengths, with symbolic byte strings of up to three bytes. A second proof models serialization for direct AES-128-GCM and A192KW and observes every encoded byte, the requested output width, and empty customization at KMAC. Native tests check the full encoding at CBOR width boundaries and exercise the real KMAC implementation. |
| ML-KEM decryption | Both recipient identity checks precede decapsulation. Direct mode uses the derived content key. Key-wrap mode requires key derivation and unwrap integrity. Only successful content authentication releases plaintext. | Separate production control-flow proofs for recipient identity, content-key establishment, and plaintext release. They model the comparison result, protected serialization and crypto providers with small direct and key-wrap fixtures. Native tests join the production parser and primitives across the supported profiles. |
| ML-KEM body authentication | The body verifier hands the AEAD adapter the selected AES-GCM registration, content key, received nonce and ciphertext, and `Enc_structure` built from the original protected bstr and external AAD. | Kani covers all three AES-GCM registrations with symbolic keys, nonces, ciphertexts, and empty or two-byte external AAD. One proof checks that the received protected bstr bypasses reserialization. A separate handoff proof models that return value and the serializer, and observes the input to the AEAD adapter. Native tests compare the shared serializer with independent bytes at the CBOR length boundaries. |

The signature obligations use the [IANA COSE registry](https://www.iana.org/assignments/cose/#algorithms)
and [RFC 9052 §4.4](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4).
The byte-string prefixes follow [RFC 8949 §3.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-3.1).
Certificate arrays follow the order specified in [RFC 9360 §2](https://www.rfc-editor.org/rfc/rfc9360.html#section-2).
The ML-KEM sizes come from [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
The ReallyMe V1 KDF context follows the field layout in the archived
[PQ KEM for COSE draft §5.1](https://datatracker.ietf.org/doc/html/draft-ietf-jose-pqc-kem-06#section-5.1).

The Sign1 regression suite exercises exact P-256 allowlist membership, every
combination of security-relevant unprotected and critical fields in a parsed
object, and the RFC 9052 encoding of an out-of-order protected map with varied
`kid`, AAD, and payload bytes.
The P-256 `kid` integration tests exercise the native validation, public
extraction, and SHA-256 paths for both registrations. The tests check
compact, full-coordinate, and private keys against independently computed
digests and compare the result with the general COSE_Key encoder for both Y
signs.
The Ed25519 `kid` regression uses [RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1)
to check the public and private key forms against one independently computed
digest. It also checks that the real parser rejects a mismatched seed and a
deprecated EdDSA registration.

The protobuf boundary tests enumerate every generated request and successful
result oneof branch. They compare each generated wire field number with the
schema and check that the response gate accepts only the matching pair. The
cross product also covers absent request and result variants.

## Comparison control-flow review

The truncated HMAC comparator was reviewed for ARM64 macOS, x86-64 Linux,
and Wasm using Rust 1.100.0 and `reallyme-crypto-constant-time` 0.3.17 and
0.4.0. Treat tag bytes as secret and pointers and lengths as public. In
`ct_eq`, the branch conditions depend on slice lengths and the loop counter.
Byte equality feeds the accumulated result through an integer AND on each
target. The loads read consecutive positions in both slices, and the
`subtle` barrier uses a fixed stack offset. Equal-length comparisons follow
the same branch and address trace across tag values. The fixed-width HMAC
registrations delegate comparison to the provider's verifier.

Reproduce the emitted comparison with the locked dependency for each target.

```sh
for comparison_target in aarch64-apple-darwin x86_64-unknown-linux-gnu wasm32-unknown-unknown; do
  cargo rustc --locked --release --target "$comparison_target" \
    -p reallyme-crypto-constant-time -- --emit=asm
done
```

The review covers the emitted comparator instructions. Microarchitectural
timing, speculation, and Wasm engine transformations require separate evidence.

## Verification scope

The proofs rely on cryptographic provider contracts for primitive correctness.
Digest uniqueness relies on SHA-256 collision resistance. The unprotected
ML-KEM encapsulation ciphertext affects authentication through the key
established by decapsulation. The serialization tests compare production
encodings with independent byte fixtures across the documented boundaries.
The comparison review specifies its targets and leakage model.

The exhaustive protobuf matrix checks the response gate. Successful execution
coverage for newly added routes belongs at the typed dispatcher and wire entry
points. Keep proofs of the cryptographic primitives with their provider. An
independent encoding equivalence proof is most valuable where a new encoding
has a wider domain than the byte fixtures can exercise.

## Running the proofs

CI uses [Kani 0.68.0](https://github.com/model-checking/kani/releases/tag/kani-0.68.0),
verifies the release bundle digest, and uploads JSON results. Each harness must
pass its assertions and unwinding checks and satisfy its reachability goals.

```sh
cargo install --locked kani-verifier --version '=0.68.0'
cargo kani setup
cargo fetch --locked
CARGO_NET_OFFLINE=true cargo kani --package reallyme-cose --lib --no-default-features --features native \
  --output-format terse -Z stubbing -Z unstable-options --harness-timeout 360s \
  --export-json target/formal-verification.json
```

Use `--harness <name>` to verify one obligation while iterating. Keep default
memory, overflow, and unwinding checks enabled. Increase a loop's unwinding
bound only when the input domain or an implementation detail warrants it.

CI allows six minutes per harness, 35 minutes for the verification step, and
45 minutes for the job. A timeout fails verification. The job summary lists
the slowest reported harnesses, and the artifact includes the console log
and any completed JSON report. Use a targeted rerun to diagnose a timeout.
Prefer proving smaller production stages with explicit assumptions and
reachability checks when a model repeatedly exhausts the time budget.
