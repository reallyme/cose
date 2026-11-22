# Running Kani proofs

Kani harnesses are colocated with the Rust implementation in
`*_proof_tests.rs`. They check algorithm/key selection, authentication inputs,
resource arithmetic and success/error gates. Providers and some parsing or
serialization stages are modeled; inspect each harness's assumptions and input
bounds before relying on its result. These proofs do not establish primitive
cryptographic correctness or constant-time execution.

Affected harnesses model Zeroize's optimization barrier as an observation that
does not change values because Kani cannot execute its inline assembly. Volatile
erasure writes remain in the analysis, with a dedicated harness checking fixed
and slice buffers. This model does not prove resistance to compiler elimination;
production builds retain the real barrier.

The [formal-verification workflow](../.github/workflows/formal-verification.yml)
runs on manual dispatch. It pins Kani 0.68.0 and verifies the release-bundle
digest. To run locally:

```sh
cargo install --locked kani-verifier --version '=0.68.0'
cargo kani setup
cargo fetch --locked
CARGO_NET_OFFLINE=true cargo kani --package reallyme-cose --lib --no-default-features --features native \
  --output-format terse -Z stubbing -Z unstable-options --harness-timeout 360s \
  --export-json target/formal-verification.json
```

Add `--harness <name>` to select one harness. Keep memory, overflow and unwinding
checks enabled. A passing run must satisfy both assertions and reachability
cover goals; check the JSON results, not only the command's exit status.
`scripts/verify_formal_obligations.sh` performs that check in CI and verifies
that the lockfile is unchanged. It requires `RUNNER_TEMP`, `jq` and `sha256sum`.

CI allows six minutes per harness and 35 minutes for verification. A timeout
fails the job. Download its JSON and console-log artifact to identify the
harness, then rerun that harness locally with the same configuration.
