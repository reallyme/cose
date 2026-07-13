#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::{cose_sign1_detached, cose_verify1_detached};

use super::support::{gen_ed25519, test_kid};

#[test]
fn cose_detached_rejects_wrong_payload() {
    let k = gen_ed25519();
    let kid = test_kid();

    let payload = b"original payload".to_vec();
    let wrong = b"tampered payload".to_vec();

    let cose = cose_sign1_detached(k.alg, &payload, &k.private, Some(kid)).expect("sign detached");

    let resolver = |k_: &[u8]| {
        if k_ == kid {
            Some(k.public.clone())
        } else {
            None
        }
    };

    let res = cose_verify1_detached(&cose, &wrong, resolver);

    assert!(res.is_err(), "verification must fail for wrong payload");
}

#[test]
fn cose_detached_with_kid_rejects_wrong_payload() {
    let k = gen_ed25519();
    let kid = test_kid();

    let payload = b"original payload".to_vec();
    let wrong = b"tampered payload".to_vec();

    let cose = cose_sign1_detached(k.alg, &payload, &k.private, Some(kid)).expect("sign detached");

    let resolver = |k_: &[u8]| {
        if k_ == kid {
            Some(k.public.clone())
        } else {
            None
        }
    };

    let res = cose_verify1_detached(&cose, &wrong, resolver);

    assert!(res.is_err(), "verification must fail for wrong payload");
}
