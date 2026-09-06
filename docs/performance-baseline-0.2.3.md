# COSE 0.2.3 Performance And Allocation Baseline

Date: 2026-09-06

These are reference measurements from the environment below after the
`buffa` 0.9.2, `reallyme-crypto` 0.3.7, and `reallyme-codec` 0.2.3 dependency
updates. Rerun the command for current timings; the allocation ceilings remain
enforced by the benchmark.

Command: `cargo bench --bench operation_performance --all-features`

Environment: Apple Silicon (`Darwin arm64`), Rust and Cargo 1.98.1,
`buffa` `0.9.2`, `reallyme-crypto` `0.3.7`, `reallyme-codec` `0.2.3`,
release profile with LTO, one code-generation unit, aborting panics, and
overflow checks. Throughput is host-specific evidence, not a cross-host release
threshold. Peak-allocation ceilings are executable review limits enforced by
the benchmark.

| Operation | Case | Median estimate | Throughput estimate | Peak live allocation |
| --- | --- | ---: | ---: | ---: |
| Sign1 verify | 4 KiB attached | 58.010 µs | 67.337 MiB/s | 8,505 bytes |
| Sign1 verify | 1 MiB detached maximum | 1.4021 ms | 713.21 MiB/s | 1,048,843 bytes |
| COSE_Key parse | Ed25519, 42 bytes | 8.9106 µs | 4.4951 MiB/s | 544 bytes |
| COSE_Key parse | ML-KEM-1024, 1,581 bytes | 57.405 µs | 26.265 MiB/s | 5,504 bytes |
| Multikey conversion | Ed25519 | 34.910 µs | n/a | 544 bytes |
| Multikey conversion | ML-KEM-1024 | 3.7495 ms | n/a | 5,495 bytes |
| COSE_Encrypt decrypt | ML-KEM-512, 4 KiB plaintext | 89.877 µs | 52.641 MiB/s | 20,340 bytes |
| COSE_Encrypt decrypt | ML-KEM-1024, 1 MiB plaintext | 3.5691 ms | 280.63 MiB/s | 4,199,828 bytes |

## Enforced Peak Limits

| Family | Reviewed ceiling |
| --- | ---: |
| Sign1 verification | 4 MiB |
| COSE_Key parsing | 1 MiB |
| Multikey conversion | 1 MiB |
| COSE_Encrypt decryption | 12 MiB |

The ceilings intentionally include margin for allocator and dependency changes
while still catching unbounded duplication. Raising a ceiling is a security
and performance policy change: record the new measurement, explain the cause,
and obtain review instead of silently replacing the baseline.

The maximum detached signing fixture proves that the documented
1,048,576-byte payload boundary is reachable through the dedicated checked
canonical encoder.
