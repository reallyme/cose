# Fuzzing

Run fuzz targets from the repository root using the toolchain pinned in the
scheduled fuzz workflow:

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
rustup toolchain install nightly-2026-09-15 --profile minimal
cargo +nightly-2026-09-15 fuzz build
cargo +nightly-2026-09-15 fuzz run cose_sign1 -- -max_total_time=900 -rss_limit_mb=4096
```

Replace `cose_sign1` with a target below.

| Target | Input boundary |
| --- | --- |
| `cose_sign1` | Attached/detached Sign1 parsing and verification |
| `cose_mac0` | Detached Mac0 headers, AAD, keys and HMAC tags |
| `cose_iso18013` | ISO Sign1 profiles and exact registration/curve policy |
| `cose_containers` | Certificate containers, peer keys, encoding and signature conversion |
| `cose_key` | COSE_Key parsing, extraction, kid and Multikey conversion |
| `multikey_to_cose` | UTF-8 Multikey parsing and key conversion |
| `wire` | Protobuf/ProtoJSON requests and response decoding |
| `cose_encrypt` | ML-KEM encryption/decryption and structured mutation |

Crash inputs are written to `fuzz/artifacts/<target>/`. Reproduce each crash
and add a deterministic regression test before removing the artifact.
Scheduled CI caches the corpus for each target.
