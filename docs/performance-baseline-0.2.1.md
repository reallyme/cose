# COSE 0.2.1 Performance And Allocation Baseline

Date: 2026-07-27

Historical release measurements; see the [0.2.3 record](performance-baseline-0.2.3.md)
for the latest baseline and the [package README](../README.md) for current behavior.

Command: `cargo bench --bench operation_performance --all-features`

Environment: Apple Silicon (`Darwin arm64`), Rust and Cargo 1.96.0, release
profile with LTO, one code-generation unit, aborting panics, and overflow
checks. Throughput is host-specific evidence, not a cross-host release
threshold. Peak-allocation ceilings are executable review limits enforced by
the benchmark.

| Operation | Case | Median estimate | Throughput estimate | Peak live allocation |
| --- | --- | ---: | ---: | ---: |
| Sign1 verify | 4 KiB attached | 56.968 µs | 68.569 MiB/s | 8,505 bytes |
| Sign1 verify | 1 MiB detached maximum | 1.4471 ms | 691.01 MiB/s | 1,048,843 bytes |
| COSE_Key parse | Ed25519, 42 bytes | 8.9757 µs | 4.4625 MiB/s | 544 bytes |
| COSE_Key parse | ML-KEM-1024, 1,581 bytes | 57.658 µs | 26.150 MiB/s | 5,504 bytes |
| Multikey conversion | Ed25519 | 26.364 µs | n/a | 544 bytes |
| Multikey conversion | ML-KEM-1024 | 3.6983 ms | n/a | 5,495 bytes |
| COSE_Encrypt decrypt | ML-KEM-512, 4 KiB plaintext | 97.352 µs | 48.599 MiB/s | 20,340 bytes |
| COSE_Encrypt decrypt | ML-KEM-1024, 1 MiB plaintext | 3.5358 ms | 283.27 MiB/s | 4,199,828 bytes |

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
