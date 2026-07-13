#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Cursor;

use ciborium::{ser::into_writer, value::Value};
use coset::{iana, CborSerializable, Label, RegisteredLabelWithPrivate};
use reallyme_cose::{
    cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_from_slice,
    cose_key_to_multikey, cose_key_to_public_bytes, cose_key_to_vec, cose_sign1, cose_verify1,
    derive_kid_from_cose_key_public, CoseError,
};

use crate::support::{gen_ed25519, gen_p256, gen_p384, sample_payload, test_kid};

#[test]
fn cose_key_rejects_duplicate_map_labels() {
    let duplicate_kty = [0xa2, 0x01, 0x01, 0x01, 0x01];

    let err = cose_key_from_slice(&duplicate_kty).expect_err("duplicate labels must be rejected");

    assert_eq!(err, CoseError::DuplicateMapLabel);
}

#[test]
fn cose_sign1_rejects_duplicate_protected_header_labels() {
    let duplicate_protected_alg = [0x84, 0x45, 0xa2, 0x01, 0x27, 0x01, 0x27, 0xa0, 0x40, 0x40];

    let err = cose_verify1(&duplicate_protected_alg, |_| None)
        .expect_err("duplicate protected labels must be rejected");

    assert_eq!(err, CoseError::DuplicateMapLabel);
}

#[test]
fn cose_sign1_rejects_duplicate_unprotected_header_labels() {
    let duplicate_unprotected_kid = [
        0x84, 0x43, 0xa1, 0x01, 0x27, 0xa2, 0x04, 0x41, 0x61, 0x04, 0x41, 0x62, 0x40, 0x40,
    ];

    let err = cose_verify1(&duplicate_unprotected_kid, |_| None)
        .expect_err("duplicate unprotected labels must be rejected");

    assert_eq!(err, CoseError::DuplicateMapLabel);
}

#[test]
fn cose_key_rejects_noncanonical_integer_labels() {
    let noncanonical_kty_label = [0xa1, 0x18, 0x01, 0x01];

    let err = cose_key_from_slice(&noncanonical_kty_label)
        .expect_err("non-minimal integer labels must be rejected");

    assert_eq!(err, CoseError::NonCanonicalCbor);
}

#[test]
fn cose_key_rejects_algorithm_key_mismatch() {
    let key = gen_p256();
    let mut cose_key =
        cose_key_from_public_bytes(key.alg, &key.public).expect("fixture COSE_Key must build");
    cose_key.alg = Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::EdDSA));

    let err =
        cose_key_to_public_bytes(&cose_key).expect_err("P-256 key with EdDSA alg must be rejected");

    assert_eq!(err, CoseError::UnsupportedAlgorithm);
}

#[test]
fn decoded_cose_key_rejects_algorithm_key_mismatch() {
    let key = gen_p256();
    let mut cose_key =
        cose_key_from_public_bytes(key.alg, &key.public).expect("fixture COSE_Key must build");
    cose_key.alg = Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::EdDSA));
    let encoded = cose_key.to_vec().expect("fixture COSE_Key must encode");

    let err = cose_key_from_slice(&encoded).expect_err("mismatched alg must fail at decode");

    assert_eq!(err, CoseError::UnsupportedAlgorithm);
}

#[test]
fn cose_key_rejects_curve_coordinate_length_mismatch() {
    let key = gen_p256();
    let mut cose_key =
        cose_key_from_public_bytes(key.alg, &key.public).expect("fixture COSE_Key must build");
    replace_param_integer(
        &mut cose_key.params,
        iana::Ec2KeyParameter::Crv as i64,
        iana::EllipticCurve::P_384 as i64,
    );
    cose_key.alg = Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES384));

    let err = cose_key_to_public_bytes(&cose_key)
        .expect_err("P-384 curve with P-256 coordinates must be rejected");

    assert_eq!(err, CoseError::InvalidKeyMaterial);
}

#[test]
fn decoded_cose_key_rejects_invalid_coordinate_length() {
    let key = gen_p256();
    let mut cose_key =
        cose_key_from_public_bytes(key.alg, &key.public).expect("fixture COSE_Key must build");
    replace_param_bytes(
        &mut cose_key.params,
        iana::Ec2KeyParameter::X as i64,
        vec![0_u8; 31],
    );
    let encoded = cose_key.to_vec().expect("fixture COSE_Key must encode");

    let err = cose_key_from_slice(&encoded).expect_err("short EC coordinate must fail at decode");

    assert_eq!(err, CoseError::InvalidKeyMaterial);
}

#[test]
fn cose_sign1_rejects_algorithm_key_mismatch_during_verification() {
    let signing_key = gen_p256();
    let wrong_curve_key = gen_p384();
    let cose = cose_sign1(
        signing_key.alg,
        &sample_payload(),
        &signing_key.private,
        Some(test_kid()),
    )
    .expect("fixture signing must succeed");

    let err = cose_verify1(&cose, |_| Some(wrong_curve_key.public.clone()))
        .expect_err("wrong curve public key must not verify");

    assert_eq!(err, CoseError::InvalidSignature);
}

#[test]
fn private_key_material_is_not_used_for_kid_or_multikey_export() {
    let key = gen_ed25519();
    let public_key =
        cose_key_from_public_bytes(key.alg, &key.public).expect("public COSE_Key must build");
    let private_key = cose_key_from_private_bytes(key.alg, &key.private, Some(&key.public))
        .expect("private COSE_Key must build");

    assert_eq!(
        derive_kid_from_cose_key_public(&private_key).expect("private kid derivation must work"),
        derive_kid_from_cose_key_public(&public_key).expect("public kid derivation must work")
    );
    assert_eq!(
        cose_key_to_multikey(&private_key).expect("private COSE_Key multikey export must work"),
        cose_key_to_multikey(&public_key).expect("public COSE_Key multikey export must work")
    );
}

#[test]
fn decoded_cose_key_reencodes_canonically() {
    let key = gen_ed25519();
    let cose_key =
        cose_key_from_public_bytes(key.alg, &key.public).expect("fixture COSE_Key must build");
    let encoded = cose_key.to_vec().expect("fixture COSE_Key must encode");
    let decoded = cose_key_from_slice(&encoded).expect("canonical COSE_Key must decode");

    assert_eq!(
        cose_key_to_vec(&decoded).expect("COSE_Key must re-encode"),
        encoded
    );
}

#[test]
fn malformed_cose_key_map_with_wrong_label_type_is_rejected() {
    let malformed = encode_value(&Value::Map(vec![(
        Value::Integer(1_i64.into()),
        Value::Text("EC2".to_owned()),
    )]));

    let err = cose_key_from_slice(&malformed).expect_err("wrong kty type must be rejected");

    assert_eq!(err, CoseError::UnsupportedAlgorithm);
}

fn replace_param_integer(params: &mut [(Label, Value)], label: i64, value: i64) {
    for (candidate, param_value) in params {
        if *candidate == Label::Int(label) {
            *param_value = Value::Integer(value.into());
            return;
        }
    }
}

fn replace_param_bytes(params: &mut [(Label, Value)], label: i64, value: Vec<u8>) {
    for (candidate, param_value) in params {
        if *candidate == Label::Int(label) {
            *param_value = Value::Bytes(value);
            return;
        }
    }
}

fn encode_value(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    into_writer(value, Cursor::new(&mut encoded)).expect("test CBOR encoding must succeed");
    encoded
}
