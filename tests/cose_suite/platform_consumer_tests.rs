#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;

use coset::{CoseSign1, TaggedCborSerializable};
use reallyme_cose::{
    cose_sign1, cose_sign1_detached_tagged, cose_sign1_tagged, cose_sign1_with_options,
    cose_verify1, cose_verify1_detached_with_policy, cose_verify1_with_metadata,
    cose_verify1_with_policy, Algorithm, CoseError, CosePolicy, CoseSign1EncodeOptions,
};

use crate::support::{gen_ed25519, gen_p256, test_kid};

const PLATFORM_COSE_SIGN1_LIMIT: usize = 512 * 1024;
const PAYLOAD_LARGER_THAN_DEFAULT_SIGN1_LIMIT: usize = 70_000;

#[test]
fn cose_sign1_tagged_emits_root_tag_18_and_verifies() {
    let key = gen_ed25519();
    let payload = b"tagged facematch-style payload";
    let tagged = cose_sign1_tagged(key.alg, payload, &key.private, Some(test_kid())).unwrap();

    assert_eq!(tagged.first(), Some(&0xd2));
    let decoded = CoseSign1::from_tagged_slice(&tagged).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(payload.as_slice()));

    let verified = cose_verify1(&tagged, |kid| {
        (kid == test_kid()).then(|| key.public.clone())
    })
    .unwrap();
    assert_eq!(verified, payload);
}

#[test]
fn cose_sign1_detached_tagged_emits_root_tag_18_and_verifies_with_policy() {
    let key = gen_ed25519();
    let payload = b"detached tagged payload";
    let tagged =
        cose_sign1_detached_tagged(key.alg, payload, &key.private, Some(test_kid())).unwrap();
    let policy = CosePolicy {
        require_kid: true,
        allowed_algs: vec![Algorithm::Ed25519],
        ..Default::default()
    };

    assert_eq!(tagged.first(), Some(&0xd2));
    let metadata = cose_verify1_detached_with_policy(&tagged, payload, &policy, |kid| {
        (kid == test_kid()).then(|| key.public.clone())
    })
    .unwrap();

    assert_eq!(metadata.alg, Algorithm::Ed25519);
    assert_eq!(metadata.kid, test_kid());
}

#[test]
fn cose_verify1_with_policy_returns_verified_payload_alg_and_kid() {
    let key = gen_p256();
    let payload = b"policy-bound payload";
    let cose = cose_sign1(key.alg, payload, &key.private, Some(test_kid())).unwrap();
    let policy = CosePolicy {
        require_kid: true,
        allowed_algs: vec![Algorithm::P256],
        ..Default::default()
    };

    let verified = cose_verify1_with_policy(&cose, &policy, |kid| {
        (kid == test_kid()).then(|| key.public.clone())
    })
    .unwrap();

    assert_eq!(verified.payload, payload);
    assert_eq!(verified.alg, Algorithm::P256);
    assert_eq!(verified.kid, test_kid());
}

#[test]
fn cose_verify1_with_metadata_uses_default_policy_and_returns_header_metadata() {
    let key = gen_ed25519();
    let payload = b"default metadata payload";
    let cose = cose_sign1(key.alg, payload, &key.private, Some(test_kid())).unwrap();

    let verified =
        cose_verify1_with_metadata(&cose, |kid| (kid == test_kid()).then(|| key.public.clone()))
            .unwrap();

    assert_eq!(verified.payload, payload);
    assert_eq!(verified.alg, Algorithm::Ed25519);
    assert_eq!(verified.kid, test_kid());
}

#[test]
fn cose_verify1_with_policy_rejects_disallowed_algorithm_before_key_resolution() {
    let key = gen_ed25519();
    let cose = cose_sign1(key.alg, b"wrong algorithm", &key.private, Some(test_kid())).unwrap();
    let resolver_called = Cell::new(false);
    let policy = CosePolicy {
        require_kid: true,
        allowed_algs: vec![Algorithm::P256],
        ..Default::default()
    };

    let result = cose_verify1_with_policy(&cose, &policy, |kid| {
        resolver_called.set(true);
        (kid == test_kid()).then(|| key.public.clone())
    });
    assert!(matches!(result, Err(CoseError::UnsupportedAlgorithm)));
    assert!(!resolver_called.get());
}

#[test]
fn attached_sign1_limit_can_be_raised_for_platform_reports() {
    let key = gen_ed25519();
    let payload = deterministic_payload(PAYLOAD_LARGER_THAN_DEFAULT_SIGN1_LIMIT);
    let cose = cose_sign1_with_options(
        key.alg,
        &payload,
        &key.private,
        Some(test_kid()),
        CoseSign1EncodeOptions {
            tag: true,
            max_cose_sign1_bytes: PLATFORM_COSE_SIGN1_LIMIT,
        },
    )
    .unwrap();
    let policy = CosePolicy {
        require_kid: true,
        allowed_algs: vec![Algorithm::Ed25519],
        max_cose_sign1_bytes: PLATFORM_COSE_SIGN1_LIMIT,
        ..Default::default()
    };

    let result = cose_verify1(&cose, |_| Some(key.public.clone()));
    assert!(matches!(result, Err(CoseError::ResourceLimitExceeded)));

    let verified = cose_verify1_with_policy(&cose, &policy, |kid| {
        (kid == test_kid()).then(|| key.public.clone())
    })
    .unwrap();
    assert_eq!(verified.payload, payload);
}

fn deterministic_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
}
