# reallyme-cose

COSE signing, verification, MACs, encryption and key formats for Rust and WASM.
Requires Rust 1.100 or later. Cryptographic operations use `reallyme-crypto`.

```toml
# Native Rust
reallyme-cose = { version = "0.3.1", default-features = false, features = ["native"] }
```

For `wasm32-unknown-unknown`, select `features = ["wasm"]` instead.
This package supplies Rust APIs and a protobuf contract; it does not ship a
Swift, Kotlin or JavaScript SDK.

Use `api::contract` for generated request/result types and `api::execute` to
execute a request. Borrowed Rust APIs cover Sign1, ISO/certificate containers,
public agreement keys, detached Mac0 and ML-KEM encryption. Generated operations
also support Sign, Mac, Encrypt0, KeySet, countersignatures and RSA verification.
See the [API reference](https://docs.rs/reallyme-cose) and
[usage guide](https://github.com/reallyme/cose/blob/main/README.md).

Supply explicit algorithm/key bindings and profile policies. Preserve received
protected-header bytes and transcript inputs. Verification does not establish
certificate trust or application authorization. Do not deduplicate or detect
replay by hashing COSE bytes: P-256/P-384/P-521 verification accepts high-S
ECDSA. Encrypt0 callers must never reuse a nonce under the same key.

Message owners wipe sensitive fields on drop; callers manage input buffers and
serialized copies. See the [operation contracts](https://github.com/reallyme/cose/blob/main/docs/message-family-support.md)
for accepted algorithms, limits and provider requirements.

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at
your option (`MIT OR Apache-2.0`). See [LICENSE](LICENSE) and [NOTICE](NOTICE).
