#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use ciborium::value::Value;
use coset::{iana, CborSerializable, CoseKeyBuilder};
use reallyme_cose::{
    cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_from_slice,
    cose_key_to_private_bytes, cose_key_to_vec, Algorithm, CoseError,
};

use super::support::{gen_ed25519, gen_p256, gen_p384, gen_p521, gen_secp256k1, gen_x25519};

#[test]
fn cose_key_ed25519_private_roundtrip() {
    let k = gen_ed25519();

    let cose_key = cose_key_from_private_bytes(k.alg, &k.private, Some(&k.public)).unwrap();
    let encoded = cose_key_to_vec(&cose_key).expect("constructed private key must be canonical");
    let reparsed = cose_key_from_slice(&encoded).expect("canonical private key must parse");
    let out = cose_key_to_private_bytes(&reparsed).unwrap();

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
fn cose_key_private_without_public_is_rejected() {
    let k = gen_ed25519();

    let result = cose_key_from_private_bytes(k.alg, &k.private, None);
    assert_eq!(
        result.err(),
        Some(reallyme_cose::CoseError::MissingKeyMaterial)
    );
}

#[test]
fn parsed_private_only_okp_key_is_rejected_without_public_binding() {
    let encoded = CoseKeyBuilder::new_okp_key()
        .param(
            iana::OkpKeyParameter::Crv as i64,
            Value::Integer((iana::EllipticCurve::Ed25519 as i64).into()),
        )
        .param(
            iana::OkpKeyParameter::D as i64,
            Value::Bytes(vec![7_u8; 32]),
        )
        .algorithm(iana::Algorithm::Ed25519)
        .build()
        .to_vec()
        .expect("test COSE_Key must encode");

    assert_eq!(
        cose_key_from_slice(&encoded).err(),
        Some(CoseError::MissingKeyMaterial),
    );
}

#[test]
fn parsed_x25519_private_key_is_rejected_as_an_unsupported_profile() {
    let private_key = gen_x25519();
    let key = Value::Map(vec![
        (
            Value::Integer((iana::KeyParameter::Kty as i64).into()),
            Value::Integer((iana::KeyType::OKP as i64).into()),
        ),
        (
            Value::Integer((iana::OkpKeyParameter::Crv as i64).into()),
            Value::Integer((iana::EllipticCurve::X25519 as i64).into()),
        ),
        (
            Value::Integer((iana::OkpKeyParameter::X as i64).into()),
            Value::Bytes(private_key.public),
        ),
        (
            Value::Integer((iana::OkpKeyParameter::D as i64).into()),
            Value::Bytes(private_key.private),
        ),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&key, &mut encoded).expect("test COSE_Key must encode");

    assert_eq!(
        cose_key_from_slice(&encoded).err(),
        Some(CoseError::UnsupportedAlgorithm),
    );
}

#[test]
fn parsed_private_only_ec2_key_is_rejected_without_public_binding() {
    let encoded = CoseKeyBuilder::default()
        .key_type(iana::KeyType::EC2)
        .param(
            iana::Ec2KeyParameter::Crv as i64,
            Value::Integer((iana::EllipticCurve::P_256 as i64).into()),
        )
        .param(
            iana::Ec2KeyParameter::D as i64,
            Value::Bytes(vec![0_u8; 32]),
        )
        .algorithm(iana::Algorithm::ESP256)
        .build()
        .to_vec()
        .expect("test COSE_Key must encode");

    assert_eq!(
        cose_key_from_slice(&encoded).err(),
        Some(CoseError::MissingKeyMaterial),
    );
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
fn cose_key_private_rejects_wrong_length_ml_kem_key() {
    let k = gen_ed25519();

    let res = cose_key_from_private_bytes(Algorithm::MlKem1024, &k.private, Some(&k.public));

    assert!(res.is_err());
}

#[test]
fn cose_key_ml_kem_private_roundtrips_and_binds_public_key() {
    let (public_key, private_key) = reallyme_crypto::ml_kem_768::generate_ml_kem_768_keypair()
        .expect("ML-KEM-768 key generation");
    let cose_key =
        cose_key_from_private_bytes(Algorithm::MlKem768, &private_key, Some(&public_key))
            .expect("build ML-KEM private COSE_Key");
    let encoded = reallyme_cose::cose_key_to_vec(&cose_key).expect("encode COSE_Key");
    let decoded = reallyme_cose::cose_key_from_slice(&encoded).expect("decode COSE_Key");

    assert_eq!(
        reallyme_cose::cose_key_to_public_bytes(&decoded).expect("extract public key"),
        public_key,
    );
    assert_eq!(
        reallyme_cose::cose_key_to_private_bytes(&decoded)
            .expect("extract private key")
            .as_slice(),
        private_key.as_slice(),
    );

    let (other_public_key, _) = reallyme_crypto::ml_kem_768::generate_ml_kem_768_keypair()
        .expect("second ML-KEM-768 key generation");
    assert_eq!(
        cose_key_from_private_bytes(Algorithm::MlKem768, &private_key, Some(&other_public_key),)
            .err(),
        Some(reallyme_cose::CoseError::InvalidKeyMaterial),
    );
}

#[test]
fn cose_key_rejects_wrong_length_ed25519_private() {
    use reallyme_cose::CoseError;

    let res = cose_key_from_private_bytes(Algorithm::Ed25519, &[7_u8; 31], None);
    assert_eq!(res.err(), Some(CoseError::InvalidKeyMaterial));
}

#[test]
fn cose_key_rejects_wrong_length_ec2_private() {
    use reallyme_cose::CoseError;

    let res = cose_key_from_private_bytes(Algorithm::P256, &[7_u8; 31], None);
    assert_eq!(res.err(), Some(CoseError::InvalidKeyMaterial));
}

#[test]
fn cose_key_rejects_mismatched_ed25519_private_and_public_keys() {
    let private = gen_ed25519();
    let public = gen_ed25519();

    let result =
        cose_key_from_private_bytes(Algorithm::Ed25519, &private.private, Some(&public.public));

    assert_eq!(
        result.err(),
        Some(reallyme_cose::CoseError::InvalidKeyMaterial)
    );
}

#[test]
fn cose_key_rejects_mismatched_p256_private_and_public_keys() {
    let private = gen_p256();
    let public = gen_p256();

    let result =
        cose_key_from_private_bytes(Algorithm::P256, &private.private, Some(&public.public));

    assert_eq!(
        result.err(),
        Some(reallyme_cose::CoseError::InvalidKeyMaterial)
    );
}
