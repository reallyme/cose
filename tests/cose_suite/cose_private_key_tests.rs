#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::{
    cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_to_private_bytes, Algorithm,
};

use super::support::{gen_ed25519, gen_p256, gen_p384, gen_p521, gen_secp256k1};

#[test]
fn cose_key_ed25519_private_roundtrip() {
    let k = gen_ed25519();

    let cose_key = cose_key_from_private_bytes(k.alg, &k.private, Some(&k.public)).unwrap();

    let out = cose_key_to_private_bytes(&cose_key).unwrap();

    assert_eq!(out.as_slice(), k.private.as_slice());
}

#[test]
fn cose_key_p256_private_roundtrip() {
    let k = gen_p256();

    let cose_key = cose_key_from_private_bytes(k.alg, &k.private, Some(&k.public)).unwrap();

    let out = cose_key_to_private_bytes(&cose_key).unwrap();

    assert_eq!(out.as_slice(), k.private.as_slice());
}

#[test]
fn cose_key_p384_private_roundtrip() {
    let k = gen_p384();

    let cose_key = cose_key_from_private_bytes(k.alg, &k.private, Some(&k.public)).unwrap();

    let out = cose_key_to_private_bytes(&cose_key).unwrap();

    assert_eq!(out.as_slice(), k.private.as_slice());
}

#[test]
fn cose_key_p521_private_roundtrip() {
    let k = gen_p521();

    let cose_key = cose_key_from_private_bytes(k.alg, &k.private, Some(&k.public)).unwrap();

    let out = cose_key_to_private_bytes(&cose_key).unwrap();

    assert_eq!(out.as_slice(), k.private.as_slice());
}

#[test]
fn cose_key_secp256k1_private_roundtrip() {
    let k = gen_secp256k1();

    let cose_key = cose_key_from_private_bytes(k.alg, &k.private, Some(&k.public)).unwrap();

    let out = cose_key_to_private_bytes(&cose_key).unwrap();

    assert_eq!(out.as_slice(), k.private.as_slice());
}

#[test]
fn cose_key_private_without_public_is_allowed() {
    let k = gen_ed25519();

    let cose_key = cose_key_from_private_bytes(k.alg, &k.private, None).unwrap();

    let out = cose_key_to_private_bytes(&cose_key).unwrap();

    assert_eq!(out.as_slice(), k.private.as_slice());
}

#[test]
fn cose_key_private_missing_d_is_rejected() {
    let k = gen_ed25519();

    // build a public-only COSE_Key
    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let res = cose_key_to_private_bytes(&cose_key);

    assert!(res.is_err());
}

#[test]
fn cose_key_private_rejects_unsupported_algorithm() {
    let k = gen_ed25519();

    let res = cose_key_from_private_bytes(Algorithm::MlDsa87, &k.private, Some(&k.public));

    assert!(res.is_err());
}

#[test]
fn cose_key_rejects_wrong_length_ed25519_private() {
    use reallyme_cose::CoseError;

    let res = cose_key_from_private_bytes(Algorithm::Ed25519, &[7_u8; 31], None);
    assert_eq!(res.unwrap_err(), CoseError::InvalidKeyMaterial);
}

#[test]
fn cose_key_rejects_wrong_length_ec2_private() {
    use reallyme_cose::CoseError;

    let res = cose_key_from_private_bytes(Algorithm::P256, &[7_u8; 31], None);
    assert_eq!(res.unwrap_err(), CoseError::InvalidKeyMaterial);
}
