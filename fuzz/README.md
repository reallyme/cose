# Fuzzing

This directory contains libFuzzer targets for the public byte boundaries that
SDKs and applications pass untrusted input to.

## Targets

- `cose_sign1`: attached and detached COSE_Sign1 verification parsing, policy,
  resource-limit, and malformed-CBOR rejection.
- `cose_key`: COSE_Key decode, canonical re-encode, public/private extraction,
  `kid` derivation, and Multikey conversion.
- `multikey_to_cose`: UTF-8 Multikey parsing and COSE_Key conversion.
- `wire`: malformed protobuf and ProtoJSON requests, operation-oneof dispatch,
  and `CoseOperationResponseV2` decoding. Each input also exercises structured
  key, attached/detached Sign1, and ML-KEM requests through binary and ProtoJSON
  adapters; UTF-8 inputs additionally exercise Multikey-to-COSE conversion.
- `cose_encrypt`: valid ML-KEM direct/AES-KW construction followed by
  structured mutation of headers, recipients, KDF-bound bytes, ciphertext,
  and tags, plus fully arbitrary decrypt input.

## Running

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
rustup toolchain install nightly-2026-07-01 --profile minimal
cargo +nightly-2026-07-01 fuzz build
cargo +nightly-2026-07-01 fuzz run cose_sign1 -- -max_total_time=900 -rss_limit_mb=4096
cargo +nightly-2026-07-01 fuzz run cose_key -- -max_total_time=900 -rss_limit_mb=4096
cargo +nightly-2026-07-01 fuzz run multikey_to_cose -- -max_total_time=900 -rss_limit_mb=4096
cargo +nightly-2026-07-01 fuzz run wire -- -max_total_time=900 -rss_limit_mb=4096
cargo +nightly-2026-07-01 fuzz run cose_encrypt -- -max_total_time=900 -rss_limit_mb=4096
```

Crash inputs are written to `fuzz/artifacts/<target>/`. Add a deterministic
regression test for any reproducible crash before removing the artifact.
Scheduled CI restores and persists a per-target corpus so later runs continue
exploring from inputs discovered by earlier runs.
