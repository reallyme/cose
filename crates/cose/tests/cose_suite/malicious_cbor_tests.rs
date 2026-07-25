#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Cursor;

use ciborium::{ser::into_writer, value::Value};
use coset::{iana, CborSerializable, ContentType, CoseSign1, RegisteredLabelWithPrivate};
use reallyme_cose::{
    cose_key_from_slice, cose_sign1, cose_verify1, limits::MAX_COSE_KEY_BYTES,
    limits::MAX_COSE_SIGN1_BYTES, CoseError,
};

use crate::support::{gen_ed25519, sample_payload, test_kid};

#[test]
fn cose_sign1_rejects_oversized_input_before_cbor_parse() {
    let oversized = vec![0_u8; MAX_COSE_SIGN1_BYTES + 1];

    let err = cose_verify1(&oversized, |_, _| None).expect_err("oversized input must be rejected");

    assert_eq!(err, CoseError::ResourceLimitExceeded);
}

#[test]
fn cose_sign1_rejects_malformed_cbor() {
    let malformed = [0xff_u8];

    let err = cose_verify1(&malformed, |_, _| None).expect_err("malformed CBOR must fail closed");

    assert_eq!(err, CoseError::Cbor);
}

#[test]
fn cose_sign1_rejects_indefinite_forms() {
    let indefinite_protected_bstr = [0x84, 0x5f, 0xff, 0xa0, 0xf6, 0x40];

    let err = cose_verify1(&indefinite_protected_bstr, |_, _| None)
        .expect_err("indefinite-length CBOR must be rejected");

    assert_eq!(err, CoseError::NonCanonicalCbor);
}

#[test]
fn cose_sign1_rejects_unexpected_top_level_tag() {
    let tagged_empty_array = [0xc1, 0x80];

    let err = cose_verify1(&tagged_empty_array, |_, _| None)
        .expect_err("unexpected top-level tags must be rejected");

    assert_eq!(err, CoseError::UnexpectedCborTag);
}

#[test]
fn cose_sign1_rejects_nested_tags() {
    let value = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(Vec::new()),
            Value::Map(Vec::new()),
            Value::Null,
            Value::Tag(1, Box::new(Value::Bytes(Vec::new()))),
        ])),
    );
    let encoded = encode_value(&value);

    let err = cose_verify1(&encoded, |_, _| None).expect_err("nested tags must be rejected");

    assert_eq!(err, CoseError::UnexpectedCborTag);
}

#[test]
fn cose_sign1_rejects_critical_protected_header() {
    let key = gen_ed25519();
    let cose_bytes = cose_sign1(key.alg, &sample_payload(), &key.private, Some(test_kid()))
        .expect("fixture signing must succeed");
    let mut cose = CoseSign1::from_slice(&cose_bytes).expect("fixture COSE must decode");
    cose.protected
        .header
        .crit
        .push(RegisteredLabelWithPrivate::Assigned(
            iana::HeaderParameter::ContentType,
        ));
    cose.protected.original_data = None;
    let mutated = cose.to_vec().expect("mutated COSE must encode");

    let err = cose_verify1(&mutated, |_, _| Some(key.public.clone()))
        .expect_err("critical headers must be rejected before crypto");

    assert_eq!(err, CoseError::UnsupportedCriticalHeader);
}

#[test]
fn cose_sign1_rejects_integrity_fields_in_unprotected_header() {
    let key = gen_ed25519();
    let cose_bytes = cose_sign1(key.alg, &sample_payload(), &key.private, Some(test_kid()))
        .expect("fixture signing must succeed");
    let mut cose = CoseSign1::from_slice(&cose_bytes).expect("fixture COSE must decode");
    cose.unprotected.key_id = b"shadow-kid".to_vec();
    let mutated = cose.to_vec().expect("mutated COSE must encode");

    let err = cose_verify1(&mutated, |_, _| Some(key.public.clone()))
        .expect_err("unprotected kid must be rejected before crypto");

    assert_eq!(err, CoseError::UnprotectedHeaderNotAllowed);
}

#[test]
fn cose_sign1_rejects_authenticated_header_semantics_not_exposed_by_the_api() {
    let key = gen_ed25519();
    let cose_bytes = cose_sign1(key.alg, &sample_payload(), &key.private, Some(test_kid()))
        .expect("fixture signing must succeed");
    let mut cose = CoseSign1::from_slice(&cose_bytes).expect("fixture COSE must decode");
    cose.protected.header.content_type =
        Some(ContentType::Text("application/reallyme-test".to_owned()));
    cose.protected.original_data = None;
    let mutated = cose.to_vec().expect("mutated COSE must encode");

    let err = cose_verify1(&mutated, |_, _| Some(key.public.clone()))
        .expect_err("unrepresented authenticated header semantics must fail closed");

    assert_eq!(err, CoseError::InvalidFormat);
}

#[test]
fn cose_sign1_rejects_invalid_signature_type_after_owning_payload() {
    let value = Value::Array(vec![
        Value::Bytes(Vec::new()),
        Value::Map(Vec::new()),
        Value::Bytes(b"sensitive rejected payload".to_vec()),
        Value::Text("not-a-signature".to_owned()),
    ]);
    let encoded = encode_value(&value);

    let err = cose_verify1(&encoded, |_, _| None)
        .expect_err("a non-byte-string signature must fail closed");

    assert_eq!(err, CoseError::InvalidSignatureEncoding);
}

#[test]
fn cose_key_rejects_oversized_input_before_cbor_parse() {
    let oversized = vec![0_u8; MAX_COSE_KEY_BYTES + 1];

    let err = cose_key_from_slice(&oversized)
        .err()
        .expect("oversized key must be rejected");

    assert_eq!(err, CoseError::ResourceLimitExceeded);
}

#[test]
fn cose_key_rejects_indefinite_forms() {
    let indefinite_map = [0xbf, 0xff];

    let err = cose_key_from_slice(&indefinite_map)
        .err()
        .expect("indefinite-length COSE_Key CBOR must be rejected");

    assert_eq!(err, CoseError::NonCanonicalCbor);
}

#[test]
fn cose_key_rejects_non_deterministic_map_order() {
    let value = Value::Map(vec![
        (
            Value::Integer((iana::KeyParameter::Alg as i64).into()),
            Value::Integer((iana::Algorithm::Ed25519 as i64).into()),
        ),
        (
            Value::Integer((iana::KeyParameter::Kty as i64).into()),
            Value::Integer((iana::KeyType::OKP as i64).into()),
        ),
        (
            Value::Integer((iana::OkpKeyParameter::Crv as i64).into()),
            Value::Integer((iana::EllipticCurve::Ed25519 as i64).into()),
        ),
        (
            Value::Integer((iana::OkpKeyParameter::X as i64).into()),
            Value::Bytes(vec![7_u8; 32]),
        ),
    ]);
    let encoded = encode_value(&value);

    let err = cose_key_from_slice(&encoded)
        .err()
        .expect("non-deterministic COSE_Key map ordering must fail");

    assert_eq!(err, CoseError::NonCanonicalCbor);
}

#[test]
fn cose_key_rejects_unexpected_tags() {
    let tagged_empty_map = [0xc1, 0xa0];

    let err = cose_key_from_slice(&tagged_empty_map)
        .err()
        .expect("COSE_Key tags must be rejected");

    assert_eq!(err, CoseError::UnexpectedCborTag);
}

#[test]
fn cose_key_rejects_excessive_nesting_before_shape_decode() {
    let mut value = Value::Null;
    for _ in 0..40 {
        value = Value::Array(vec![value]);
    }
    let encoded = encode_value(&value);

    let err = cose_key_from_slice(&encoded)
        .err()
        .expect("deep nesting must be rejected");

    assert_eq!(err, CoseError::ResourceLimitExceeded);
}

fn encode_value(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    into_writer(value, Cursor::new(&mut encoded)).expect("test CBOR encoding must succeed");
    encoded
}
