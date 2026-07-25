// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Throughput and peak-allocation baselines for the COSE operation families.

use std::hint::black_box;
use std::time::Duration;

use allocation_counter::measure;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use reallyme_cose::{
    cose_decrypt_ml_kem, cose_encrypt_ml_kem_direct, cose_key_from_public_bytes,
    cose_key_from_slice, cose_key_to_multikey, cose_key_to_vec, cose_sign1, cose_sign1_detached,
    cose_verify1_detached_with_policy, cose_verify1_with_policy, derive_kid_from_cose_key_public,
    Algorithm, CoseContentEncryptionAlgorithm, CoseMlKemAlgorithm, CoseMlKemDecryptRequest,
    CoseMlKemEncryptRequest, CosePolicy,
};
use reallyme_crypto::dispatch::generate_keypair;
use zeroize::Zeroizing;

const REALISTIC_PAYLOAD_BYTES: usize = 4_096;
const MAX_DETACHED_PAYLOAD_BYTES: usize = 1_048_576;
const SIGN1_PEAK_ALLOCATION_LIMIT: u64 = 4 * 1_048_576;
const KEY_PEAK_ALLOCATION_LIMIT: u64 = 1_048_576;
const MULTIKEY_PEAK_ALLOCATION_LIMIT: u64 = 1_048_576;
const DECRYPT_PEAK_ALLOCATION_LIMIT: u64 = 12 * 1_048_576;
const BENCHMARK_SAMPLE_SIZE: usize = 10;

struct SignFixture {
    cose: Zeroizing<Vec<u8>>,
    payload: Zeroizing<Vec<u8>>,
    public_key: Zeroizing<Vec<u8>>,
    detached: bool,
}

struct DecryptFixture {
    cose_encrypt: Zeroizing<Vec<u8>>,
    private_key: Zeroizing<Vec<u8>>,
    kid: Zeroizing<Vec<u8>>,
}

fn benchmark_operations(c: &mut Criterion) {
    let realistic_sign = sign_fixture(REALISTIC_PAYLOAD_BYTES, false);
    let maximum_sign = sign_fixture(MAX_DETACHED_PAYLOAD_BYTES, true);
    let (realistic_key, maximum_key) = key_fixtures();
    let realistic_decrypt = decrypt_fixture(CoseMlKemAlgorithm::MlKem512, REALISTIC_PAYLOAD_BYTES);
    let maximum_decrypt =
        decrypt_fixture(CoseMlKemAlgorithm::MlKem1024, MAX_DETACHED_PAYLOAD_BYTES);

    assert_peak_allocation(
        "sign1_verify_realistic",
        SIGN1_PEAK_ALLOCATION_LIMIT,
        || verify_sign(&realistic_sign),
    );
    assert_peak_allocation("sign1_verify_maximum", SIGN1_PEAK_ALLOCATION_LIMIT, || {
        verify_sign(&maximum_sign)
    });
    assert_peak_allocation(
        "cose_key_parse_realistic",
        KEY_PEAK_ALLOCATION_LIMIT,
        || cose_key_from_slice(&realistic_key),
    );
    assert_peak_allocation(
        "cose_key_parse_maximum_profile",
        KEY_PEAK_ALLOCATION_LIMIT,
        || cose_key_from_slice(&maximum_key),
    );
    let maximum_key_owner =
        cose_key_from_slice(&maximum_key).unwrap_or_else(|error| benchmark_setup_failed(error));
    assert_peak_allocation("multikey_realistic", MULTIKEY_PEAK_ALLOCATION_LIMIT, || {
        let key = cose_key_from_slice(&realistic_key)
            .unwrap_or_else(|error| benchmark_setup_failed(error));
        cose_key_to_multikey(&key)
    });
    assert_peak_allocation(
        "multikey_maximum_profile",
        MULTIKEY_PEAK_ALLOCATION_LIMIT,
        || cose_key_to_multikey(&maximum_key_owner),
    );
    assert_peak_allocation("decrypt_realistic", DECRYPT_PEAK_ALLOCATION_LIMIT, || {
        decrypt(&realistic_decrypt)
    });
    assert_peak_allocation("decrypt_maximum", DECRYPT_PEAK_ALLOCATION_LIMIT, || {
        decrypt(&maximum_decrypt)
    });

    let mut sign_group = c.benchmark_group("sign1_verify");
    bench_sign(&mut sign_group, "realistic", &realistic_sign);
    bench_sign(&mut sign_group, "maximum_detached", &maximum_sign);
    sign_group.finish();

    let mut key_group = c.benchmark_group("cose_key_parse");
    key_group.throughput(Throughput::Bytes(
        realistic_key.len().try_into().unwrap_or(u64::MAX),
    ));
    key_group.bench_with_input(
        BenchmarkId::new("realistic", realistic_key.len()),
        &realistic_key,
        |b, input| {
            b.iter(|| black_box(cose_key_from_slice(black_box(input))));
        },
    );
    key_group.throughput(Throughput::Bytes(
        maximum_key.len().try_into().unwrap_or(u64::MAX),
    ));
    key_group.bench_with_input(
        BenchmarkId::new("maximum_profile", maximum_key.len()),
        &maximum_key,
        |b, input| {
            b.iter(|| black_box(cose_key_from_slice(black_box(input))));
        },
    );
    key_group.finish();

    let realistic_key_owner =
        cose_key_from_slice(&realistic_key).unwrap_or_else(|error| benchmark_setup_failed(error));
    let mut multikey_group = c.benchmark_group("multikey_conversion");
    multikey_group.bench_function("realistic", |b| {
        b.iter(|| black_box(cose_key_to_multikey(black_box(&realistic_key_owner))));
    });
    multikey_group.bench_function("maximum_profile", |b| {
        b.iter(|| black_box(cose_key_to_multikey(black_box(&maximum_key_owner))));
    });
    multikey_group.finish();

    let mut decrypt_group = c.benchmark_group("cose_encrypt_decrypt");
    bench_decrypt(&mut decrypt_group, "realistic", &realistic_decrypt);
    bench_decrypt(&mut decrypt_group, "maximum", &maximum_decrypt);
    decrypt_group.finish();
}

fn bench_sign(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
    fixture: &SignFixture,
) {
    group.throughput(Throughput::Bytes(
        fixture.payload.len().try_into().unwrap_or(u64::MAX),
    ));
    group.bench_function(name, |b| {
        b.iter(|| {
            verify_sign(black_box(fixture));
            black_box(())
        })
    });
}

fn bench_decrypt(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
    fixture: &DecryptFixture,
) {
    group.throughput(Throughput::Bytes(
        fixture.cose_encrypt.len().try_into().unwrap_or(u64::MAX),
    ));
    group.bench_function(name, |b| {
        b.iter(|| {
            decrypt(black_box(fixture));
            black_box(())
        })
    });
}

#[allow(clippy::print_stderr)]
fn assert_peak_allocation<T>(name: &str, limit: u64, operation: impl FnOnce() -> T) {
    let info = measure(|| drop(black_box(operation())));
    assert!(
        info.bytes_max <= limit,
        "{name} exceeded its reviewed peak allocation limit"
    );
    eprintln!(
        "allocation {name}: peak={} total={} count={}",
        info.bytes_max, info.bytes_total, info.count_total
    );
}

fn sign_fixture(payload_len: usize, detached: bool) -> SignFixture {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).unwrap_or_else(|error| benchmark_setup_failed(error));
    let payload = Zeroizing::new(vec![0x5a; payload_len]);
    let cose = if detached {
        cose_sign1_detached(
            Algorithm::Ed25519,
            &payload,
            &private_key,
            Some(b"benchmark-key"),
        )
    } else {
        cose_sign1(
            Algorithm::Ed25519,
            &payload,
            &private_key,
            Some(b"benchmark-key"),
        )
    }
    .unwrap_or_else(|error| benchmark_setup_failed(error));
    SignFixture {
        cose,
        payload,
        public_key: Zeroizing::new(public_key),
        detached,
    }
}

fn verify_sign(fixture: &SignFixture) {
    let policy = CosePolicy::new().allow_algorithm(Algorithm::Ed25519);
    let result = if fixture.detached {
        cose_verify1_detached_with_policy(&fixture.cose, &fixture.payload, &policy, |_, _| {
            Some(fixture.public_key.to_vec())
        })
        .map(|_| ())
    } else {
        cose_verify1_with_policy(&fixture.cose, &policy, |_, _| {
            Some(fixture.public_key.to_vec())
        })
        .map(|_| ())
    };
    if let Err(error) = result {
        benchmark_setup_failed(error);
    }
}

fn key_fixtures() -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let (ed_public, _) =
        generate_keypair(Algorithm::Ed25519).unwrap_or_else(|error| benchmark_setup_failed(error));
    let ed_key = cose_key_from_public_bytes(Algorithm::Ed25519, &ed_public)
        .unwrap_or_else(|error| benchmark_setup_failed(error));
    let realistic = cose_key_to_vec(&ed_key).unwrap_or_else(|error| benchmark_setup_failed(error));

    let (ml_kem_public, _) = reallyme_crypto::ml_kem_1024::generate_ml_kem_1024_keypair()
        .unwrap_or_else(|error| benchmark_setup_failed(error));
    let ml_kem_key = cose_key_from_public_bytes(Algorithm::MlKem1024, &ml_kem_public)
        .unwrap_or_else(|error| benchmark_setup_failed(error));
    let maximum =
        cose_key_to_vec(&ml_kem_key).unwrap_or_else(|error| benchmark_setup_failed(error));
    (realistic, maximum)
}

fn decrypt_fixture(algorithm: CoseMlKemAlgorithm, plaintext_len: usize) -> DecryptFixture {
    let crypto_algorithm = match algorithm {
        CoseMlKemAlgorithm::MlKem512 => Algorithm::MlKem512,
        CoseMlKemAlgorithm::MlKem768 => Algorithm::MlKem768,
        CoseMlKemAlgorithm::MlKem1024 => Algorithm::MlKem1024,
        _ => benchmark_setup_failed("unrecognized ML-KEM benchmark algorithm"),
    };
    let (public_key, private_key) =
        generate_keypair(crypto_algorithm).unwrap_or_else(|error| benchmark_setup_failed(error));
    let key = cose_key_from_public_bytes(crypto_algorithm, &public_key)
        .unwrap_or_else(|error| benchmark_setup_failed(error));
    let kid =
        derive_kid_from_cose_key_public(&key).unwrap_or_else(|error| benchmark_setup_failed(error));
    let plaintext = Zeroizing::new(vec![0xa5; plaintext_len]);
    let request = CoseMlKemEncryptRequest::new(
        algorithm,
        CoseContentEncryptionAlgorithm::Aes256Gcm,
        &public_key,
        &kid,
        &plaintext,
        None,
    );
    let cose_encrypt =
        cose_encrypt_ml_kem_direct(&request).unwrap_or_else(|error| benchmark_setup_failed(error));
    DecryptFixture {
        cose_encrypt,
        private_key,
        kid,
    }
}

fn decrypt(fixture: &DecryptFixture) {
    let request = CoseMlKemDecryptRequest::new(
        &fixture.cose_encrypt,
        &fixture.private_key,
        &fixture.kid,
        None,
    );
    if let Err(error) = cose_decrypt_ml_kem(&request) {
        benchmark_setup_failed(error);
    }
}

#[allow(clippy::print_stderr)]
fn benchmark_setup_failed(error: impl core::fmt::Debug) -> ! {
    eprintln!("benchmark fixture or operation failed: {error:?}");
    std::process::exit(1)
}

fn configured_criterion() -> Criterion {
    Criterion::default()
        .sample_size(BENCHMARK_SAMPLE_SIZE)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(1))
}

criterion_group! {
    name = benches;
    config = configured_criterion();
    targets = benchmark_operations
}
criterion_main!(benches);
