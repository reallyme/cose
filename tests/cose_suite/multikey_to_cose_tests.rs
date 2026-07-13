#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_codec::multikey::encode_multikey;
use reallyme_cose::{
    cose_key_from_public_bytes, cose_key_to_multikey, cose_key_to_public_bytes,
    multikey_to_cose_key, CoseError,
};

use super::support::{gen_ed25519, gen_p256, gen_p384, gen_p521, gen_secp256k1, gen_x25519};

#[test]
fn multikey_to_cose_ed25519_roundtrip() {
    let k = gen_ed25519();

    let cose = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk = cose_key_to_multikey(&cose).unwrap();

    let cose2 = multikey_to_cose_key(&mk).unwrap();

    let out = cose_key_to_public_bytes(&cose2).unwrap();

    assert_eq!(out, k.public);
}

#[test]
fn multikey_to_cose_x25519_roundtrip() {
    let k = gen_x25519();

    let cose = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk = cose_key_to_multikey(&cose).unwrap();

    let cose2 = multikey_to_cose_key(&mk).unwrap();

    let out = cose_key_to_public_bytes(&cose2).unwrap();

    assert_eq!(out, k.public);
}

#[test]
fn multikey_to_cose_p256_roundtrip() {
    let k = gen_p256();

    let cose = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk = cose_key_to_multikey(&cose).unwrap();

    let cose2 = multikey_to_cose_key(&mk).unwrap();

    let out = cose_key_to_public_bytes(&cose2).unwrap();

    assert_eq!(out, k.public);
}

#[test]
fn multikey_to_cose_p384_roundtrip() {
    let k = gen_p384();

    let cose = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk = cose_key_to_multikey(&cose).unwrap();

    let cose2 = multikey_to_cose_key(&mk).unwrap();

    let out = cose_key_to_public_bytes(&cose2).unwrap();

    assert_eq!(out, k.public);
}

#[test]
fn multikey_to_cose_p521_roundtrip() {
    let k = gen_p521();

    let cose = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk = cose_key_to_multikey(&cose).unwrap();

    let cose2 = multikey_to_cose_key(&mk).unwrap();

    let out = cose_key_to_public_bytes(&cose2).unwrap();

    assert_eq!(out, k.public);
}

#[test]
fn multikey_to_cose_secp256k1_roundtrip() {
    let k = gen_secp256k1();

    let cose = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk = cose_key_to_multikey(&cose).unwrap();

    let cose2 = multikey_to_cose_key(&mk).unwrap();

    let out = cose_key_to_public_bytes(&cose2).unwrap();

    assert_eq!(out, k.public);
}

#[test]
fn multikey_to_cose_rejects_unknown_codec() {
    let bad = "zThisIsNotAValidMultikey";

    let res = multikey_to_cose_key(bad);

    assert!(res.is_err());
}

#[test]
fn multikey_to_cose_rejects_algorithm_unsupported_by_current_mapping() {
    const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2_592;

    let multikey = encode_multikey("mldsa-87-pub", &[0u8; ML_DSA_87_PUBLIC_KEY_LEN]).unwrap();

    let res = multikey_to_cose_key(&multikey);

    assert!(matches!(res.unwrap_err(), CoseError::UnsupportedAlgorithm));
}

#[test]
fn multikey_to_cose_is_deterministic() {
    let k = gen_ed25519();

    let cose = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk = cose_key_to_multikey(&cose).unwrap();

    let cose1 = multikey_to_cose_key(&mk).unwrap();
    let cose2 = multikey_to_cose_key(&mk).unwrap();

    let out1 = cose_key_to_public_bytes(&cose1).unwrap();
    let out2 = cose_key_to_public_bytes(&cose2).unwrap();

    assert_eq!(out1, out2);
}
