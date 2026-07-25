// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! WASM runtime tests for the COSE_Sign1 boundary.

#![allow(clippy::expect_used, missing_docs)]
#![cfg(all(feature = "wasm", target_arch = "wasm32"))]

use reallyme_cose::{cose_sign1, cose_verify1, Algorithm, CoseError};
use wasm_bindgen_test::wasm_bindgen_test;

// RFC 8032 test vector 1 is public test material, not a deployed secret.
const ED25519_PRIVATE_KEY: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const ED25519_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const KEY_ID: &[u8] = b"wasm-ed25519-rfc8032-1";
const PAYLOAD: &[u8] = b"ReallyMe COSE wasm runtime test";

#[wasm_bindgen_test]
fn sign1_roundtrip_and_tamper_rejection_execute_in_wasm() {
    let encoded = cose_sign1(
        Algorithm::Ed25519,
        PAYLOAD,
        &ED25519_PRIVATE_KEY,
        Some(KEY_ID),
    )
    .expect("RFC 8032 key must sign in the wasm lane");

    let verified = cose_verify1(&encoded, |_, kid| {
        (kid == KEY_ID).then(|| ED25519_PUBLIC_KEY.to_vec())
    })
    .expect("matching RFC 8032 key must verify in the wasm lane");
    assert_eq!(verified.as_slice(), PAYLOAD);

    let mut tampered = encoded;
    let signature_byte = tampered
        .last_mut()
        .expect("COSE_Sign1 encoding must contain a signature byte");
    *signature_byte ^= 0x01;
    let result = cose_verify1(&tampered, |_, kid| {
        (kid == KEY_ID).then(|| ED25519_PUBLIC_KEY.to_vec())
    });
    assert_eq!(result.err(), Some(CoseError::InvalidSignature));
}
