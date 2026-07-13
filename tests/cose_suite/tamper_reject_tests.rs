#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::support::{gen_ed25519, sample_payload, test_kid};

use reallyme_cose::{cose_sign1, cose_verify1};

#[test]
fn cose_rejects_tampered_payload() {
    let k = gen_ed25519();
    let payload = sample_payload();
    let kid = test_kid();

    let cose = cose_sign1(k.alg, &payload, &k.private, Some(kid)).unwrap();

    let mut tampered = cose.clone();

    // Flip last byte
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;

    let resolver = |k_: &[u8]| {
        if k_ == kid {
            Some(k.public.clone())
        } else {
            None
        }
    };

    assert!(cose_verify1(&tampered, resolver).is_err());
}
