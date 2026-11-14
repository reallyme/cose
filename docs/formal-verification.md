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
| Sign1 policy | Restricted policies require exact COSE registration membership, including for ES256 and ESP256. | Every generated selector against every ordered allowlist of zero to two generated selectors, including duplicates. |
| Sign1 authenticated bytes | The verifier's input builder preserves the original protected bstr, external AAD, and payload, in order and with the `Signature1` context. It rejects a missing original bstr. | An out-of-order protected map with a symbolic `kid`, and symbolic one-byte AAD and payload. |
| Sign1 authentication gate | Attached and detached verification enforce payload placement before resolving the protected algorithm and `kid`. The verification flow passes the received protected bytes, AAD and intended payload to the structure builder, then forwards the builder output, resolved key and signature to the backend. Only backend acceptance releases authenticated metadata and, for attached verification, the payload. | An Ed25519 fixture with symbolic embedded-payload presence and backend acceptance. Stubs model wire decoding, protected-byte preflight, policy, the structure builder, signature conversion, fixture wiping and cryptographic verification. |
| Sign1 P-256 dispatch | The shared attached and detached verifier resolves the original ES256 or ESP256 registration with the protected `kid`. Each registration reaches the P-256 backend with its own resolved key. An unresolved key, `kid` mismatch, or algorithm mismatch returns its typed reason before structure construction, signature conversion, or backend verification. | Decoded fixtures with one protected `kid` and distinct resolver results for ES256 and ESP256. The proofs exercise production algorithm selection and resolver handling. They model protected-byte preflight, default policy, structure building, signature conversion, and cryptographic verification. Recursive cleanup of the public fixtures is outside the model. |
| Sign1 `x5chain` trust gate | Missing placement, an empty chain, and an unprotected chain without opt-in are rejected before trust resolution. For a permitted placement, the trust resolver receives the exact algorithm and decoded chain. A rejected lookup returns `KeyNotResolved` before structure building, signature conversion, or backend verification. | A borrowed, decoded Ed25519 fixture with symbolic placement, chain presence, and unprotected opt-in. The placement check and resolver handling run in production code. The harness models protected-byte preflight, general Sign1 policy, structure building, signature conversion, and cryptographic verification. Wire decoding and cleanup of the synthetic fixture are outside the model. The native regression covers both accepted and rejected trust lookups for each permitted placement. |
| P-256 public extraction | The extractor returns exactly the compressed SEC1 prefix and the supplied X coordinate. The private scalar `d` cannot affect those bytes or substitute for missing `x` or `y`. Full-coordinate extraction returns a point only after provider acceptance. | Bounded parameter slices with symbolic 32-byte X, Y, and `d` and symbolic compact Y sign. The production label lookup and projection run for compact and full-coordinate inputs. Full-point validation is modeled as acceptance or typed rejection. The model omits recursive cleanup for the synthetic CBOR fixtures. |
| P-256 `kid` hash input | The fixed-size public encoder passes only `kty`, `alg`, `crv`, `x`, and the Y sign to SHA-256, preserving ES256 (`-7`) and ESP256 (`-9`) exactly. An unsupported registration or invalid compressed-point prefix cannot reach the hash. | All 32 X bytes and both Y signs at the production hash boundary. The encoder takes a compressed public point and an exact registration, and has no private-key input. The harness observes the input to SHA-256 through a stub. |
| Authentication lengths | CBOR byte-string sizing accounts for the correct prefix width and fails on overflow. | Every pair of 64-bit `usize` inputs to the size helper. |
| ML-KEM recipient registration | Each private-use ID selects the documented mode, parameter set, wire lengths, and optional AES-KW registration and key length. Unknown private-use IDs fail closed. | All `i64` values supplied as private-use labels. |

The signature obligations use the [IANA COSE registry](https://www.iana.org/assignments/cose/#algorithms)
and [RFC 9052 §4.4](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4).
The ML-KEM sizes come from [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).

The Sign1 regression suite exercises exact P-256 allowlist membership, every
combination of security-relevant unprotected and critical fields in a parsed
object, and the RFC 9052 encoding of an out-of-order protected map with varied
`kid`, AAD, and payload bytes.
The P-256 `kid` integration tests exercise the native validation, public
extraction, and SHA-256 paths for both registrations. The tests check
compact, full-coordinate, and private keys against independently computed
digests and compare the result with the general COSE_Key encoder for both Y
signs.

## Remaining 0.4.0 verification work

| Priority | Area | Method and acceptance condition |
| --- | --- | --- |
| 1 | Sign1 verification | Connect the `x5chain` trust gate to wire decoding. Prove that label 33 yields the correct placement and that duplicate chains across header buckets fail before trust resolution. Extend proofs to longer allowlists and larger signed fields. |
| 2 | COSE_Key and `kid` | Extend private-field exclusion and hash-input checks to other key families. Extend the extraction model to additional parameter layouts and cover the documented defaults for keys with an omitted `alg`. The P-256 proof distinguishes preimages. Digest uniqueness relies on SHA-256's collision resistance. |
| 3 | ML-KEM composition | Check the production KDF context against an independent byte specification. Model key derivation, decapsulation, unwrap, and AES-GCM through typed results at the crypto boundary. Prove both recipient identity checks precede decapsulation and plaintext is returned only after required key establishment and content authentication. The unprotected encapsulation ciphertext affects authentication through the established key. |
| 4 | Mac0 and signature representation | Check the `MAC0` context, detached payload, AAD, protected headers, HMAC registration and exact tag length. Verify DER/raw conversion against width and canonical DER rules while preserving the existing NIST-curve verification semantics. Evaluate constant-time comparison with a leakage-aware method. |
| 5 | Resource limits and operation routing | Check COSE-specific length, depth, and work limits at the parser boundaries. Extend the existing protobuf contract checks to assert matching successful request/result variants across all routes. |

Start with Kani for control flow and finite input domains. Use independent
byte specifications and differential tests for larger serialization domains.
Consider Cryptol and SAW once the ML-KEM context specification is stable and
there is a maintained equivalence check against the production encoder.
The proofs rely on the cryptographic provider's contract for primitive
correctness. They establish neither side-channel resistance nor properties
of the wasm runtime.

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
