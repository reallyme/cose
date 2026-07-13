#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::{cose_key_from_public_bytes, cose_key_to_public_bytes, Algorithm};

use super::support::{gen_ed25519, gen_p256, gen_p384, gen_p521, gen_secp256k1};

#[test]
fn cose_key_ed25519_roundtrip() {
    let k = gen_ed25519();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let out = cose_key_to_public_bytes(&cose_key).unwrap();

    assert_eq!(out, k.public);
}

#[test]
fn cose_key_p256_roundtrip() {
    let k = gen_p256();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let out = cose_key_to_public_bytes(&cose_key).unwrap();

    assert_eq!(out, k.public);
}

#[test]
fn cose_key_p384_roundtrip() {
    let k = gen_p384();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let out = cose_key_to_public_bytes(&cose_key).unwrap();

    assert_eq!(out, k.public);
}

#[test]
fn cose_key_p521_roundtrip() {
    let k = gen_p521();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let out = cose_key_to_public_bytes(&cose_key).unwrap();

    assert_eq!(out, k.public);
}

#[test]
fn cose_key_secp256k1_roundtrip() {
    let k = gen_secp256k1();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let out = cose_key_to_public_bytes(&cose_key).unwrap();

    assert_eq!(out, k.public);
}

#[test]
fn cose_key_rejects_invalid_ec_length() {
    let bad = vec![0u8; 10];

    let res = cose_key_from_public_bytes(Algorithm::P256, &bad);

    assert!(res.is_err());
}

#[test]
fn cose_key_rejects_unsupported_algorithm() {
    let k = gen_ed25519();

    let res = cose_key_from_public_bytes(Algorithm::MlDsa87, &k.public);

    assert!(res.is_err());
}

#[test]
fn cose_key_rejects_wrong_length_ed25519_public() {
    use reallyme_cose::CoseError;

    for len in [0_usize, 31, 33] {
        let res = cose_key_from_public_bytes(Algorithm::Ed25519, &vec![7_u8; len]);
        assert_eq!(res.unwrap_err(), CoseError::InvalidKeyMaterial, "len {len}");
    }
}

#[test]
fn cose_key_rejects_wrong_length_x25519_public() {
    use reallyme_cose::CoseError;

    let res = cose_key_from_public_bytes(Algorithm::X25519, &[7_u8; 31]);
    assert_eq!(res.unwrap_err(), CoseError::InvalidKeyMaterial);
}
