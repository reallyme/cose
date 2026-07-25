#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::{
    cose_sign1, cose_verify1, cose_verify1_with_policy, Algorithm, CoseError, CosePolicy,
};

use super::support::{gen_ed25519, gen_p384, gen_p521, test_kid, TestKey};

#[test]
fn policy_rejects_missing_kid() {
    let policy = CosePolicy::new().with_require_kid(true);

    let k = gen_ed25519();

    let cose_bytes = cose_sign1(
        k.alg, b"hello", &k.private, None, // no kid
    )
    .unwrap();

    let result = cose_verify1_with_policy(&cose_bytes, &policy, |_, _| Some(k.public.clone()));
    assert!(matches!(result, Err(CoseError::MissingKid)));
}

#[test]
fn policy_allows_p384_when_explicitly_allowed() {
    let k = gen_p384();

    policy_allows_algorithm(&k, Algorithm::P384);
}

#[test]
fn policy_allows_p521_when_explicitly_allowed() {
    let k = gen_p521();

    policy_allows_algorithm(&k, Algorithm::P521);
}

#[test]
fn verify_uses_kid_for_key_selection() {
    let k = gen_ed25519();
    let kid = test_kid();

    let cose_bytes = cose_sign1(k.alg, b"hello", &k.private, Some(kid)).unwrap();

    let resolver = |_, k_: &[u8]| {
        if k_ == kid {
            Some(k.public.clone())
        } else {
            None
        }
    };

    let payload = cose_verify1(&cose_bytes, resolver).unwrap();

    assert_eq!(payload.as_slice(), b"hello");
}

#[test]
fn verify_fails_with_unknown_kid() {
    let k = gen_ed25519();

    let cose_bytes = cose_sign1(k.alg, b"hello", &k.private, Some(b"unknown")).unwrap();

    let resolver = |_, _k: &[u8]| None;

    assert_eq!(
        cose_verify1(&cose_bytes, resolver).unwrap_err(),
        CoseError::KeyNotResolved
    );
}

fn policy_allows_algorithm(k: &TestKey, alg: Algorithm) {
    let policy = CosePolicy::new().allow_algorithm(alg);

    let cose_bytes = cose_sign1(k.alg, b"hello", &k.private, Some(test_kid())).unwrap();

    let payload = cose_verify1_with_policy(&cose_bytes, &policy, |_, kid| {
        (kid == test_kid()).then(|| k.public.clone())
    })
    .unwrap();
    assert_eq!(payload.payload.as_slice(), b"hello");
}

#[test]
fn verify_allows_empty_kid_when_resolver_accepts_default_key() {
    let k = gen_ed25519();

    let cose_bytes = cose_sign1(k.alg, b"hello", &k.private, None).unwrap();

    let resolver = |_, kid: &[u8]| {
        if kid.is_empty() {
            Some(k.public.clone())
        } else {
            None
        }
    };

    let payload = cose_verify1(&cose_bytes, resolver).unwrap();

    assert_eq!(payload.as_slice(), b"hello");
}

#[test]
fn verify_fails_with_missing_kid_when_default_key_is_not_resolved() {
    let k = gen_ed25519();

    let cose_bytes = cose_sign1(k.alg, b"hello", &k.private, None).unwrap();

    let resolver = |_, _kid: &[u8]| None;

    assert_eq!(
        cose_verify1(&cose_bytes, resolver).unwrap_err(),
        CoseError::MissingKid
    );
}
