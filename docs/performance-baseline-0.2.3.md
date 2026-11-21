# Performance reference: 0.2.3

These measurements are for 0.2.3, not the current dependency set. They were
recorded on 2026-09-06 on Apple Silicon with Rust/Cargo 1.98.1, Buffa 0.9.2,
Crypto 0.3.7 and Codec 0.2.3. Timings are host-specific. Measure the current
checkout with:

```sh
cargo bench --bench operation_performance --all-features
```

| Operation | Case | Median | Throughput | Peak live allocation |
| --- | --- | ---: | ---: | ---: |
| Sign1 verify | 4 KiB attached | 58.010 µs | 67.337 MiB/s | 8,505 bytes |
| Sign1 verify | 1 MiB detached | 1.4021 ms | 713.21 MiB/s | 1,048,843 bytes |
| COSE_Key parse | Ed25519, 42 bytes | 8.9106 µs | 4.4951 MiB/s | 544 bytes |
| COSE_Key parse | ML-KEM-1024, 1,581 bytes | 57.405 µs | 26.265 MiB/s | 5,504 bytes |
| Multikey conversion | Ed25519 | 34.910 µs | n/a | 544 bytes |
| Multikey conversion | ML-KEM-1024 | 3.7495 ms | n/a | 5,495 bytes |
| Encrypt decrypt | ML-KEM-512, 4 KiB plaintext | 89.877 µs | 52.641 MiB/s | 20,340 bytes |
| Encrypt decrypt | ML-KEM-1024, 1 MiB plaintext | 3.5691 ms | 280.63 MiB/s | 4,199,828 bytes |

The benchmark also enforces peak-allocation ceilings:

| Family | Ceiling |
| --- | ---: |
| Sign1 verification | 4 MiB |
| COSE_Key parsing | 1 MiB |
| Multikey conversion | 1 MiB |
| Encrypt decryption | 12 MiB |
