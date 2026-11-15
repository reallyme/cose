#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_cose::{
    cose_sign1, cose_sign1_detached, cose_verify1_detached,
    cose_verify1_detached_with_exact_algorithm, cose_verify1_with_exact_algorithm, CoseError,
    CosePolicy, CoseSignatureAlgorithm,
};

use super::support::{gen_ed25519, test_kid};

#[test]
fn cose_detached_rejects_wrong_payload() {
    let k = gen_ed25519();
    let kid = test_kid();

    let payload = b"original payload".to_vec();
    let wrong = b"tampered payload".to_vec();

    let cose = cose_sign1_detached(k.alg, &payload, &k.private, Some(kid)).expect("sign detached");

    let resolver = |_, k_: &[u8]| {
        if k_ == kid {
            Some(k.public.clone())
        } else {
            None
        }
    };

    let res = cose_verify1_detached(&cose, &wrong, resolver);

    assert!(matches!(res, Err(CoseError::InvalidSignature)));
}

#[test]
fn cose_detached_with_kid_rejects_wrong_payload() {
    let k = gen_ed25519();
    let kid = test_kid();

    let payload = b"original payload".to_vec();
    let wrong = b"tampered payload".to_vec();

    let cose = cose_sign1_detached(k.alg, &payload, &k.private, Some(kid)).expect("sign detached");

    let resolver = |_, k_: &[u8]| {
        if k_ == kid {
            Some(k.public.clone())
        } else {
            None
        }
    };

    let res = cose_verify1_detached(&cose, &wrong, resolver);

    assert!(matches!(res, Err(CoseError::InvalidSignature)));
}

#[test]
fn exact_sign1_verifiers_reject_mismatched_payload_placement_before_key_resolution(
) -> Result<(), CoseError> {
    let key = gen_ed25519();
    let kid = test_kid();
    let payload = b"payload";
    let policy = CosePolicy::new().allow_cose_algorithm(CoseSignatureAlgorithm::Ed25519);
    let attached = cose_sign1(key.alg, payload, &key.private, Some(kid))?;
    let detached = cose_sign1_detached(key.alg, payload, &key.private, Some(kid))?;

    let mut resolver_calls = 0;
    let mut resolve = |algorithm, requested_kid: &[u8]| {
        resolver_calls += 1;
        assert_eq!(algorithm, CoseSignatureAlgorithm::Ed25519);
        assert_eq!(requested_kid, kid);
        Some(key.public.clone())
    };

    assert!(matches!(
        cose_verify1_with_exact_algorithm(&detached, &[], &policy, &mut resolve),
        Err(CoseError::MissingPayload)
    ));
    assert!(matches!(
        cose_verify1_detached_with_exact_algorithm(&attached, payload, &[], &policy, &mut resolve),
        Err(CoseError::InvalidFormat)
    ));
    assert_eq!(resolver_calls, 0);
    Ok(())
}
