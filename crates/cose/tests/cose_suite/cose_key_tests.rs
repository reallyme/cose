#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::{cose_key_from_public_bytes, cose_key_to_public_bytes, Algorithm, CoseError};

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
fn cose_key_rejects_off_curve_raw_and_uncompressed_points() {
    for key in [gen_p256(), gen_p384(), gen_p521(), gen_secp256k1()] {
        let uncompressed =
            uncompressed_public_key(&key).expect("fixture must use a supported EC algorithm");
        let raw = uncompressed
            .get(1..)
            .expect("fixed SEC1 fixture must contain a prefix");
        let _ = cose_key_from_public_bytes(key.alg, raw)
            .expect("valid raw point must remain supported");
        let _ = cose_key_from_public_bytes(key.alg, &uncompressed)
            .expect("valid uncompressed point must remain supported");

        let mut invalid_uncompressed = uncompressed;
        let last = invalid_uncompressed
            .last_mut()
            .expect("fixed SEC1 fixture must contain coordinates");
        *last = last.wrapping_add(2);
        let invalid_raw = invalid_uncompressed
            .get(1..)
            .expect("fixed SEC1 fixture must contain a prefix");

        assert_eq!(
            cose_key_from_public_bytes(key.alg, invalid_raw).err(),
            Some(CoseError::InvalidKeyMaterial),
            "{:?}",
            key.alg,
        );
        assert_eq!(
            cose_key_from_public_bytes(key.alg, &invalid_uncompressed).err(),
            Some(CoseError::InvalidKeyMaterial),
            "{:?}",
            key.alg,
        );
    }
}

fn uncompressed_public_key(key: &super::support::TestKey) -> Option<Vec<u8>> {
    match key.alg {
        Algorithm::P256 => Some(
            reallyme_crypto::p256::decompress_public_key(&key.public)
                .expect("P-256 fixture must decompress"),
        ),
        Algorithm::P384 => Some(
            reallyme_crypto::p384::decompress_p384(&key.public)
                .expect("P-384 fixture must decompress"),
        ),
        Algorithm::P521 => Some(
            reallyme_crypto::p521::decompress_p521(&key.public)
                .expect("P-521 fixture must decompress"),
        ),
        Algorithm::Secp256k1 => {
            let (x, y) = reallyme_crypto::secp256k1::decompress_public_key(&key.public)
                .expect("secp256k1 fixture must decompress");
            let mut uncompressed = Vec::with_capacity(65);
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(&x);
            uncompressed.extend_from_slice(&y);
            Some(uncompressed)
        }
        _ => None,
    }
}

#[test]
fn cose_key_rejects_wrong_length_ml_kem_public_key() {
    let k = gen_ed25519();

    let res = cose_key_from_public_bytes(Algorithm::MlKem1024, &k.public);

    assert!(res.is_err());
}

#[test]
fn cose_key_ml_kem_public_roundtrips() {
    let keypairs = [
        (
            Algorithm::MlKem512,
            reallyme_crypto::ml_kem_512::generate_ml_kem_512_keypair()
                .expect("ML-KEM-512 key generation"),
        ),
        (
            Algorithm::MlKem768,
            reallyme_crypto::ml_kem_768::generate_ml_kem_768_keypair()
                .expect("ML-KEM-768 key generation"),
        ),
        (
            Algorithm::MlKem1024,
            reallyme_crypto::ml_kem_1024::generate_ml_kem_1024_keypair()
                .expect("ML-KEM-1024 key generation"),
        ),
    ];

    for (algorithm, (public_key, _)) in keypairs {
        let cose_key = cose_key_from_public_bytes(algorithm, &public_key)
            .expect("build ML-KEM public COSE_Key");
        let encoded = reallyme_cose::cose_key_to_vec(&cose_key).expect("encode COSE_Key");
        let decoded = reallyme_cose::cose_key_from_slice(&encoded).expect("decode COSE_Key");
        assert_eq!(
            cose_key_to_public_bytes(&decoded).expect("extract public key"),
            public_key,
        );
    }
}

#[test]
fn cose_key_rejects_wrong_length_ed25519_public() {
    use reallyme_cose::CoseError;

    for len in [0_usize, 31, 33] {
        let res = cose_key_from_public_bytes(Algorithm::Ed25519, &vec![7_u8; len]);
        assert_eq!(res.err(), Some(CoseError::InvalidKeyMaterial), "len {len}");
    }
}

#[test]
fn cose_key_rejects_wrong_length_x25519_public() {
    use reallyme_cose::CoseError;

    let res = cose_key_from_public_bytes(Algorithm::X25519, &[7_u8; 31]);
    assert_eq!(res.err(), Some(CoseError::InvalidKeyMaterial));
}

#[test]
fn cose_key_rejects_all_canonical_x25519_low_order_public_keys() {
    use reallyme_cose::CoseError;

    // Canonical low-order Montgomery encodings from curve25519-dalek's
    // X25519_LOW_ORDER_POINTS table. Pinning the full set here proves the COSE
    // key boundary preserves reallyme-crypto's contributory-behavior policy.
    for encoded in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        let public_key = decode_hex_32(encoded).expect("fixed X25519 test vector must decode");
        let result = cose_key_from_public_bytes(Algorithm::X25519, &public_key);
        assert_eq!(
            result.err(),
            Some(CoseError::InvalidKeyMaterial),
            "{encoded}"
        );
    }
}

#[test]
fn cose_key_rejects_all_known_ed25519_low_order_public_key_encodings() {
    use reallyme_cose::CoseError;

    // These are the canonical low-order Edwards encodings and non-canonical
    // aliases documented by the C2SP CCTV Ed25519 corpus. The primitive corpus
    // remains in reallyme-crypto; this pins the COSE boundary's stricter policy.
    for encoded in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ] {
        let public_key = decode_hex_32(encoded).expect("fixed Ed25519 test vector must decode");
        let result = cose_key_from_public_bytes(Algorithm::Ed25519, &public_key);
        assert_eq!(
            result.err(),
            Some(CoseError::InvalidKeyMaterial),
            "{encoded}"
        );
    }
}

fn decode_hex_32(encoded: &str) -> Option<[u8; 32]> {
    if encoded.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (slot, pair) in output.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        *slot = high.checked_mul(16)?.checked_add(low)?;
    }
    Some(output)
}

const fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
