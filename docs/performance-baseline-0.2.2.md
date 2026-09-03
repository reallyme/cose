<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# COSE 0.2.2 Performance And Allocation Baseline

Date: 2026-09-03

Command: `cargo bench --bench operation_performance --all-features`

Environment: Apple Silicon (`Darwin arm64`), `reallyme-crypto` `0.3.5`, release
profile with LTO, one code-generation unit, aborting panics, and overflow
checks. Throughput is host-specific evidence, not a cross-host release
threshold. Peak-allocation ceilings are executable review limits enforced by
the benchmark.

| Operation | Case | Median estimate | Throughput estimate | Peak live allocation |
| --- | --- | ---: | ---: | ---: |
| Sign1 verify | 4 KiB attached | 58.374 µs | 66.918 MiB/s | 8,505 bytes |
| Sign1 verify | 1 MiB detached maximum | 1.4443 ms | 692.39 MiB/s | 1,048,843 bytes |
| COSE_Key parse | Ed25519, 42 bytes | 9.3920 µs | 4.2647 MiB/s | 544 bytes |
| COSE_Key parse | ML-KEM-1024, 1,581 bytes | 59.105 µs | 25.510 MiB/s | 5,504 bytes |
| Multikey conversion | Ed25519 | 35.862 µs | n/a | 544 bytes |
| Multikey conversion | ML-KEM-1024 | 3.9646 ms | n/a | 5,495 bytes |
| COSE_Encrypt decrypt | ML-KEM-512, 4 KiB plaintext | 91.821 µs | 51.526 MiB/s | 20,340 bytes |
| COSE_Encrypt decrypt | ML-KEM-1024, 1 MiB plaintext | 3.6824 ms | 271.99 MiB/s | 4,199,828 bytes |

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

Every native Sign1 key resolver receives `(expected_algorithm, protected_kid)`.
Resolvers must use that tuple as the key-store lookup identity and return only
a public key registered for both values; resolving by `kid` alone discards the
algorithm-binding guarantee. `VerifiedCoseSign1::cose_algorithm` retains the
exact COSE registration, including the distinction between ES256 (`-7`) and
ESP256 (`-9`). The protobuf lane expresses the same restriction through its
exact algorithm allow-list and trusted `expected_kid` input.

The protobuf operation lane is capped independently at 2 MiB for request
messages and caller-supplied per-operation COSE/payload limits. Native Rust APIs
may opt into larger local limits directly; protobuf callers cannot raise their
parse policy beyond the message envelope cap.
