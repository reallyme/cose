<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Fuzzing

This directory contains libFuzzer targets for the public byte boundaries that
SDKs and applications pass untrusted input to.

## Targets

- `cose_sign1`: attached and detached COSE_Sign1 verification parsing, policy,
  resource-limit, and malformed-CBOR rejection.
- `cose_key`: COSE_Key decode, canonical re-encode, public/private extraction,
  `kid` derivation, and Multikey conversion.
- `multikey_to_cose`: UTF-8 Multikey parsing and COSE_Key conversion.

## Running

```sh
cargo install cargo-fuzz --locked
cargo +nightly fuzz build
cargo +nightly fuzz run cose_sign1 -- -max_total_time=300 -rss_limit_mb=4096
cargo +nightly fuzz run cose_key -- -max_total_time=300 -rss_limit_mb=4096
cargo +nightly fuzz run multikey_to_cose -- -max_total_time=300 -rss_limit_mb=4096
```

Crash inputs are written to `fuzz/artifacts/<target>/`. Add a deterministic
regression test for any reproducible crash before removing the artifact.
