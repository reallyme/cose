#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::{
    cose_sign1, cose_verify1, validate_cose_sign1_policy, Algorithm, CoseError, CosePolicy,
};

use coset::{CborSerializable, CoseSign1};

use super::support::{gen_ed25519, gen_p384, gen_p521, test_kid, TestKey};

#[test]
fn policy_rejects_missing_kid() {
    let policy = CosePolicy {
        require_kid: true,
        ..Default::default()
    };

    let k = gen_ed25519();

    let cose_bytes = cose_sign1(
        k.alg, b"hello", &k.private, None, // no kid
    )
    .unwrap();

    let cose = CoseSign1::from_slice(&cose_bytes).unwrap();

    assert!(validate_cose_sign1_policy(&cose, &policy).is_err());
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

    let resolver = |k_: &[u8]| {
        if k_ == kid {
            Some(k.public.clone())
        } else {
            None
        }
    };

    let payload = cose_verify1(&cose_bytes, resolver).unwrap();

    assert_eq!(payload, b"hello");
}

#[test]
fn verify_fails_with_unknown_kid() {
    let k = gen_ed25519();

    let cose_bytes = cose_sign1(k.alg, b"hello", &k.private, Some(b"unknown")).unwrap();

    let resolver = |_k: &[u8]| None;

    assert_eq!(
        cose_verify1(&cose_bytes, resolver).unwrap_err(),
        CoseError::KeyNotResolved
    );
}

fn policy_allows_algorithm(k: &TestKey, alg: Algorithm) {
    let policy = CosePolicy {
        allowed_algs: vec![alg],
        ..Default::default()
    };

    let cose_bytes = cose_sign1(k.alg, b"hello", &k.private, Some(test_kid())).unwrap();

    let cose = CoseSign1::from_slice(&cose_bytes).unwrap();

    validate_cose_sign1_policy(&cose, &policy).unwrap();
}

#[test]
fn verify_allows_empty_kid_when_resolver_accepts_default_key() {
    let k = gen_ed25519();

    let cose_bytes = cose_sign1(k.alg, b"hello", &k.private, None).unwrap();

    let resolver = |kid: &[u8]| {
        if kid.is_empty() {
            Some(k.public.clone())
        } else {
            None
        }
    };

    let payload = cose_verify1(&cose_bytes, resolver).unwrap();

    assert_eq!(payload, b"hello");
}

#[test]
fn verify_fails_with_missing_kid_when_default_key_is_not_resolved() {
    let k = gen_ed25519();

    let cose_bytes = cose_sign1(k.alg, b"hello", &k.private, None).unwrap();

    let resolver = |_kid: &[u8]| None;

    assert_eq!(
        cose_verify1(&cose_bytes, resolver).unwrap_err(),
        CoseError::MissingKid
    );
}
