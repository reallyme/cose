#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::{
    cose_key_from_private_bytes, cose_key_from_public_bytes, derive_kid_from_cose_key_public,
};

use super::support::{gen_ed25519, gen_p256, gen_p384, gen_p521, gen_secp256k1};

#[test]
fn kid_is_stable_for_same_public_key() {
    let k = gen_ed25519();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let kid1 = derive_kid_from_cose_key_public(&cose_key).unwrap();
    let kid2 = derive_kid_from_cose_key_public(&cose_key).unwrap();

    assert_eq!(kid1, kid2);
}

#[test]
fn kid_ignores_private_key_material() {
    let k = gen_ed25519();

    let public_only = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let with_private = cose_key_from_private_bytes(k.alg, &k.private, Some(&k.public)).unwrap();

    let kid_pub = derive_kid_from_cose_key_public(&public_only).unwrap();
    let kid_priv = derive_kid_from_cose_key_public(&with_private).unwrap();

    assert_eq!(kid_pub, kid_priv);
}

#[test]
fn kid_differs_for_different_keys() {
    let k1 = gen_ed25519();
    let k2 = gen_ed25519();

    let key1 = cose_key_from_public_bytes(k1.alg, &k1.public).unwrap();
    let key2 = cose_key_from_public_bytes(k2.alg, &k2.public).unwrap();

    let kid1 = derive_kid_from_cose_key_public(&key1).unwrap();
    let kid2 = derive_kid_from_cose_key_public(&key2).unwrap();

    assert_ne!(kid1, kid2);
}

#[test]
fn kid_is_stable_for_ec_p256() {
    let k = gen_p256();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let kid1 = derive_kid_from_cose_key_public(&cose_key).unwrap();
    let kid2 = derive_kid_from_cose_key_public(&cose_key).unwrap();

    assert_eq!(kid1, kid2);
}

#[test]
fn kid_is_stable_for_ec_p384() {
    let k = gen_p384();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let kid1 = derive_kid_from_cose_key_public(&cose_key).unwrap();
    let kid2 = derive_kid_from_cose_key_public(&cose_key).unwrap();

    assert_eq!(kid1, kid2);
}

#[test]
fn kid_is_stable_for_ec_p521() {
    let k = gen_p521();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let kid1 = derive_kid_from_cose_key_public(&cose_key).unwrap();
    let kid2 = derive_kid_from_cose_key_public(&cose_key).unwrap();

    assert_eq!(kid1, kid2);
}

#[test]
fn kid_is_stable_for_ec_secp256k1() {
    let k = gen_secp256k1();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let kid1 = derive_kid_from_cose_key_public(&cose_key).unwrap();
    let kid2 = derive_kid_from_cose_key_public(&cose_key).unwrap();

    assert_eq!(kid1, kid2);
}

#[test]
fn kid_length_is_sha256() {
    let k = gen_ed25519();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let kid = derive_kid_from_cose_key_public(&cose_key).unwrap();

    assert_eq!(kid.len(), 32);
}
