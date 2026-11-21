# COSE test vectors

The JSON suites contain fixed COSE encodings, authentication structures, key
projections and encryption results. `manifest.json` records each suite's exact
SHA-256 digest and case count. Keep those entries in sync when changing vectors.

Run the independent COSE-layer auditor from the repository root:

```sh
cargo run --locked --manifest-path tools/vector-audit/Cargo.toml --bin reallyme-cose-vector-audit -- .
```

The auditor uses direct RustCrypto dependencies rather than the production
ReallyMe facades. It is an independent check of COSE processing, not an
independent implementation of the cryptographic primitives.

Preserve exact protected-header and authentication-structure bytes. Algorithm
registrations are distinct even when they share a primitive. The
`cose-sign1-ed25519-node-openssl` case uses RFC 8032 key material and an
OpenSSL-generated signature for registration `-19`; retain that independent
answer rather than regenerating it through production code.
