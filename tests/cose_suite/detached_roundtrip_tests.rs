#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::support::{gen_ed25519, sample_payload, test_kid};

use reallyme_cose::{cose_sign1_detached, cose_verify1_detached};

#[test]
fn cose_detached_roundtrip() {
    let k = gen_ed25519();
    let payload = sample_payload();
    let kid = test_kid();

    let cose = cose_sign1_detached(k.alg, &payload, &k.private, Some(kid)).unwrap();

    let resolver = |k_: &[u8]| {
        if k_ == kid {
            Some(k.public.clone())
        } else {
            None
        }
    };

    let res = cose_verify1_detached(&cose, &payload, resolver);

    assert!(res.is_ok());
}

#[test]
fn cose_detached_allows_empty_kid_when_resolver_accepts_default_key() {
    let k = gen_ed25519();
    let payload = sample_payload();

    let cose = cose_sign1_detached(k.alg, &payload, &k.private, None).unwrap();

    let resolver = |kid: &[u8]| {
        if kid.is_empty() {
            Some(k.public.clone())
        } else {
            None
        }
    };

    let res = cose_verify1_detached(&cose, &payload, resolver);

    assert!(res.is_ok());
}
