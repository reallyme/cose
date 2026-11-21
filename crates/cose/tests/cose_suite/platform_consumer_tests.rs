#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::Cell;

use coset::{CoseSign1, TaggedCborSerializable};
use reallyme_cose::{
    cose_sign1, cose_sign1_detached_tagged, cose_sign1_tagged, cose_sign1_with_options,
    cose_verify1, cose_verify1_detached_with_policy, cose_verify1_with_metadata,
    cose_verify1_with_policy, Algorithm, CoseError, CosePolicy, CoseSign1EncodeOptions,
};

use crate::support::{gen_ed25519, gen_p256, test_kid};

const PAYLOAD_LARGER_THAN_DEFAULT_SIGN1_LIMIT: usize = 70_000;

#[test]
fn cose_sign1_tagged_emits_root_tag_18_and_verifies() {
    let key = gen_ed25519();
    let payload = b"tagged facematch-style payload";
    let tagged = cose_sign1_tagged(key.alg, payload, &key.private, Some(test_kid())).unwrap();

    assert_eq!(tagged.first(), Some(&0xd2));
    let decoded = CoseSign1::from_tagged_slice(&tagged).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(payload.as_slice()));

    let verified = cose_verify1(&tagged, |_, kid| {
        (kid == test_kid()).then(|| key.public.clone())
    })
    .unwrap();
    assert_eq!(verified.as_slice(), payload);
}

#[test]
fn cose_sign1_detached_tagged_emits_root_tag_18_and_verifies_with_policy() {
    let key = gen_ed25519();
    let payload = b"detached tagged payload";
    let tagged =
        cose_sign1_detached_tagged(key.alg, payload, &key.private, Some(test_kid())).unwrap();
    let policy = CosePolicy::new()
        .with_require_kid(true)
        .allow_algorithm(Algorithm::Ed25519);

    assert_eq!(tagged.first(), Some(&0xd2));
    let metadata = cose_verify1_detached_with_policy(&tagged, payload, &policy, |_, kid| {
        (kid == test_kid()).then(|| key.public.clone())
    })
    .unwrap();

    assert_eq!(metadata.alg, Algorithm::Ed25519);
    assert_eq!(metadata.kid.as_slice(), test_kid());
}

#[test]
fn cose_verify1_with_policy_returns_verified_payload_alg_and_kid() {
    let key = gen_p256();
    let payload = b"policy-bound payload";
    let cose = cose_sign1(key.alg, payload, &key.private, Some(test_kid())).unwrap();
    let policy = CosePolicy::new()
        .with_require_kid(true)
        .allow_algorithm(Algorithm::P256);

    let verified = cose_verify1_with_policy(&cose, &policy, |_, kid| {
        (kid == test_kid()).then(|| key.public.clone())
    })
    .unwrap();

    assert_eq!(verified.payload.as_slice(), payload);
    assert_eq!(verified.alg, Algorithm::P256);
    assert_eq!(verified.kid.as_slice(), test_kid());
}

#[test]
fn cose_verify1_with_metadata_uses_default_policy_and_returns_header_metadata() {
    let key = gen_ed25519();
    let payload = b"default metadata payload";
    let cose = cose_sign1(key.alg, payload, &key.private, Some(test_kid())).unwrap();

    let verified = cose_verify1_with_metadata(&cose, |_, kid| {
        (kid == test_kid()).then(|| key.public.clone())
    })
    .unwrap();

    assert_eq!(verified.payload.as_slice(), payload);
    assert_eq!(verified.alg, Algorithm::Ed25519);
    assert_eq!(verified.kid.as_slice(), test_kid());
}

#[test]
fn cose_verify1_with_policy_rejects_disallowed_algorithm_before_key_resolution() {
    let key = gen_ed25519();
    let cose = cose_sign1(key.alg, b"wrong algorithm", &key.private, Some(test_kid())).unwrap();
    let resolver_called = Cell::new(false);
    let policy = CosePolicy::new()
        .with_require_kid(true)
        .allow_algorithm(Algorithm::P256);

    let result = cose_verify1_with_policy(&cose, &policy, |_, kid| {
        resolver_called.set(true);
        (kid == test_kid()).then(|| key.public.clone())
    });
    assert!(matches!(result, Err(CoseError::UnsupportedAlgorithm)));
    assert!(!resolver_called.get());
}

#[test]
fn attached_sign1_limits_cannot_exceed_the_schema_maximum() {
    let key = gen_ed25519();
    let payload = deterministic_payload(PAYLOAD_LARGER_THAN_DEFAULT_SIGN1_LIMIT);
    let unsupported_limit = reallyme_cose::limits::MAX_COSE_SIGN1_ENCODED_BYTES
        .checked_add(1)
        .unwrap();
    let rejected = cose_sign1_with_options(
        key.alg,
        &payload,
        &key.private,
        Some(test_kid()),
        CoseSign1EncodeOptions::tagged().with_max_cose_sign1_bytes(unsupported_limit),
    );
    assert_eq!(rejected.err(), Some(CoseError::ResourceLimitExceeded));
    let policy = CosePolicy::new()
        .with_require_kid(true)
        .allow_algorithm(Algorithm::Ed25519)
        .with_max_cose_sign1_bytes(unsupported_limit);

    // Encode an oversized input independently so verification must reject it
    // before key resolution, even when the caller requests a larger ceiling.
    let fixture = cose_sign1_tagged(key.alg, b"small", &key.private, Some(test_kid())).unwrap();
    let mut oversized = CoseSign1::from_tagged_slice(&fixture).unwrap();
    oversized.payload = Some(payload);
    let oversized = oversized.to_tagged_vec().unwrap();
    let result = cose_verify1(&oversized, |_, _| Some(key.public.clone()));
    assert!(matches!(result, Err(CoseError::ResourceLimitExceeded)));

    let resolver_called = Cell::new(false);
    let rejected = cose_verify1_with_policy(&oversized, &policy, |_, _| {
        resolver_called.set(true);
        Some(key.public.clone())
    });
    assert_eq!(rejected.err(), Some(CoseError::ResourceLimitExceeded));
    assert!(!resolver_called.get());
}

fn deterministic_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
}
