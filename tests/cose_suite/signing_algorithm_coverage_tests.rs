#![allow(missing_docs, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use coset::{CborSerializable, CoseSign1};
use reallyme_cose::{cose_sign1, cose_sign1_detached, cose_verify1, cose_verify1_detached};

use crate::support::{
    gen_ed25519, gen_p256, gen_p384, gen_p521, gen_secp256k1, sample_payload, TestKey,
};

type SigningCase = (&'static str, fn() -> TestKey, usize);

#[test]
fn all_supported_signing_algorithms_roundtrip_attached_and_detached() {
    // Expected signature widths are the RFC 9053 / RFC 8032 fixed encodings:
    // Ed25519 = 64, ECDSA = 2 * coordinate width.
    let cases: [SigningCase; 5] = [
        ("EdDSA", gen_ed25519, 64),
        ("ES256", gen_p256, 64),
        ("ES384", gen_p384, 96),
        ("ES512", gen_p521, 132),
        ("ES256K", gen_secp256k1, 64),
    ];

    for (label, make_key, expected_signature_len) in cases {
        let key = make_key();
        let kid = label.as_bytes();
        let payload = sample_payload();

        let attached = cose_sign1(key.alg, &payload, &key.private, Some(kid)).unwrap();
        let decoded = CoseSign1::from_slice(&attached).unwrap();
        assert_eq!(
            decoded.signature.len(),
            expected_signature_len,
            "signature width for {label}"
        );
        let attached_payload = cose_verify1(&attached, |requested_kid| {
            if requested_kid == kid {
                Some(key.public.clone())
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(attached_payload, payload, "attached COSE_Sign1 {label}");

        let detached = cose_sign1_detached(key.alg, &payload, &key.private, Some(kid)).unwrap();
        cose_verify1_detached(&detached, &payload, |requested_kid| {
            if requested_kid == kid {
                Some(key.public.clone())
            } else {
                None
            }
        })
        .unwrap();
    }
}
