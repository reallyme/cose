#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::{cose_key_from_public_bytes, cose_key_to_multikey, Algorithm};

use super::support::{gen_ed25519, gen_p256, gen_p384, gen_p521, gen_secp256k1, gen_x25519};

#[test]
fn cose_key_ed25519_to_multikey() {
    let k = gen_ed25519();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk = cose_key_to_multikey(&cose_key).unwrap();

    assert!(mk.starts_with("z"));
}

#[test]
fn cose_key_x25519_to_multikey() {
    let k = gen_x25519();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk = cose_key_to_multikey(&cose_key).unwrap();

    assert!(mk.starts_with("z"));
}

#[test]
fn cose_key_p256_to_multikey() {
    let k = gen_p256();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk = cose_key_to_multikey(&cose_key).unwrap();

    assert!(mk.starts_with("z"));
}

#[test]
fn cose_key_p384_to_multikey() {
    let k = gen_p384();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk = cose_key_to_multikey(&cose_key).unwrap();

    assert!(mk.starts_with("z"));
}

#[test]
fn cose_key_p521_to_multikey() {
    let k = gen_p521();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk = cose_key_to_multikey(&cose_key).unwrap();

    assert!(mk.starts_with("z"));
}

#[test]
fn cose_key_secp256k1_to_multikey() {
    let k = gen_secp256k1();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk = cose_key_to_multikey(&cose_key).unwrap();

    assert!(mk.starts_with("z"));
}

#[test]
fn cose_key_to_multikey_is_deterministic() {
    let k = gen_ed25519();

    let cose_key = cose_key_from_public_bytes(k.alg, &k.public).unwrap();

    let mk1 = cose_key_to_multikey(&cose_key).unwrap();
    let mk2 = cose_key_to_multikey(&cose_key).unwrap();

    assert_eq!(mk1, mk2);
}

#[test]
fn cose_key_to_multikey_rejects_unsupported_algorithm() {
    let k = gen_ed25519();

    let cose_key = cose_key_from_public_bytes(Algorithm::MlDsa87, &k.public);

    assert!(cose_key.is_err());
}
