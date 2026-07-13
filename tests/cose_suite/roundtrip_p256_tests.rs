#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use super::support::{gen_p256, gen_p384, gen_p521, sample_payload, TestKey};

use reallyme_cose::{cose_sign1, cose_verify1};

#[test]
fn cose_p256_roundtrip() {
    let k = gen_p256();
    cose_ec2_roundtrip(&k);
}

#[test]
fn cose_p384_roundtrip() {
    let k = gen_p384();
    cose_ec2_roundtrip(&k);
}

#[test]
fn cose_p521_roundtrip() {
    let k = gen_p521();
    cose_ec2_roundtrip(&k);
}

fn cose_ec2_roundtrip(k: &TestKey) {
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
