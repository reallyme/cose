#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::support::{gen_secp256k1, sample_payload};

use reallyme_cose::{cose_sign1, cose_verify1};

#[test]
fn cose_secp256k1_roundtrip() {
    let k = gen_secp256k1();
    let payload = sample_payload();
    let kid = b"test-key";

    let cose = cose_sign1(k.alg, &payload, &k.private, Some(kid)).unwrap();

    let resolver = |k_: &[u8]| {
        if k_ == kid {
            Some(k.public.clone())
        } else {
            None
        }
    };

    cose_verify1(&cose, resolver).unwrap();
}
