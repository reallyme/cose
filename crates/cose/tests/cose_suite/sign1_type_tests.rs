#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::Cell;

use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1, Label, TaggedCborSerializable};
use reallyme_cose::{
    cose_sign1_detached_with_options, cose_sign1_with_options, cose_verify1_detached_with_policy,
    cose_verify1_with_policy, CoseError, CosePolicy, CoseSign1EncodeOptions, CoseType,
    MAX_COSE_TYPE_TEXT_BYTES,
};

use crate::support::{gen_ed25519, test_kid};

const STATUS_LIST_CWT_MEDIA_TYPE: &str = "application/statuslist+cwt";
const STATUS_LIST_CWT_CONTENT_FORMAT: u64 = 279;
const COSE_TYPE_HEADER_LABEL: i64 = 16;

#[test]
fn tagged_sign1_round_trips_authenticated_text_type() {
    let key = gen_ed25519();
    let payload = b"status list claims";
    let options = CoseSign1EncodeOptions::tagged()
        .with_protected_type(CoseType::Text(STATUS_LIST_CWT_MEDIA_TYPE.to_owned()));
    let encoded =
        cose_sign1_with_options(key.alg, payload, &key.private, Some(test_kid()), options)
            .expect("typed tagged Sign1 must encode");

    let parsed = CoseSign1::from_tagged_slice(&encoded).expect("tagged Sign1 must parse");
    assert_eq!(
        parsed.protected.header.rest,
        vec![(
            Label::Int(COSE_TYPE_HEADER_LABEL),
            Value::Text(STATUS_LIST_CWT_MEDIA_TYPE.to_owned()),
        )]
    );

    let policy = CosePolicy::new().with_require_tagged_sign1(true);
    let verified = cose_verify1_with_policy(&encoded, &policy, |_, kid| {
        (kid == test_kid()).then(|| key.public.clone())
    })
    .expect("typed tagged Sign1 must verify");

    assert_eq!(verified.payload.as_slice(), payload);
    assert_eq!(
        verified.cose_type,
        Some(CoseType::Text(STATUS_LIST_CWT_MEDIA_TYPE.to_owned()))
    );
}

#[test]
fn tagged_sign1_round_trips_registered_type() {
    let key = gen_ed25519();
    let options = CoseSign1EncodeOptions::tagged()
        .with_protected_type(CoseType::Registered(STATUS_LIST_CWT_CONTENT_FORMAT));
    let encoded = cose_sign1_with_options(
        key.alg,
        b"status list claims",
        &key.private,
        Some(test_kid()),
        options,
    )
    .expect("registered typed Sign1 must encode");
    let policy = CosePolicy::new().with_require_tagged_sign1(true);

    let verified = cose_verify1_with_policy(&encoded, &policy, |_, _| Some(key.public.clone()))
        .expect("registered typed Sign1 must verify");

    assert_eq!(
        verified.cose_type,
        Some(CoseType::Registered(STATUS_LIST_CWT_CONTENT_FORMAT))
    );
}

#[test]
fn detached_sign1_returns_authenticated_type_metadata() {
    let key = gen_ed25519();
    let payload = b"detached status list claims";
    let options = CoseSign1EncodeOptions::tagged()
        .with_protected_type(CoseType::Registered(STATUS_LIST_CWT_CONTENT_FORMAT));
    let encoded =
        cose_sign1_detached_with_options(key.alg, payload, &key.private, Some(test_kid()), options)
            .expect("detached typed Sign1 must encode");
    let policy = CosePolicy::new().with_require_tagged_sign1(true);

    let verified = cose_verify1_detached_with_policy(&encoded, payload, &policy, |_, _| {
        Some(key.public.clone())
    })
    .expect("detached typed Sign1 must verify");

    assert_eq!(
        verified.cose_type,
        Some(CoseType::Registered(STATUS_LIST_CWT_CONTENT_FORMAT))
    );
}

#[test]
fn changing_protected_type_invalidates_signature() {
    let key = gen_ed25519();
    let encoded = cose_sign1_with_options(
        key.alg,
        b"status list claims",
        &key.private,
        Some(test_kid()),
        CoseSign1EncodeOptions::tagged()
            .with_protected_type(CoseType::Text(STATUS_LIST_CWT_MEDIA_TYPE.to_owned())),
    )
    .expect("typed tagged Sign1 must encode");
    let mut cose = CoseSign1::from_tagged_slice(&encoded).expect("tagged Sign1 must parse");
    for (label, value) in &mut cose.protected.header.rest {
        if *label == Label::Int(COSE_TYPE_HEADER_LABEL) {
            *value = Value::Text("application/other+cwt".to_owned());
        }
    }
    cose.protected.original_data = None;
    let tampered = cose
        .to_tagged_vec()
        .expect("tampered tagged Sign1 must encode");

    let error = cose_verify1_with_policy(
        &tampered,
        &CosePolicy::new().with_require_tagged_sign1(true),
        |_, _| Some(key.public.clone()),
    )
    .err()
    .expect("changing protected type must invalidate the signature");

    assert_eq!(error, CoseError::InvalidSignature);
}

#[test]
fn tag_requirement_rejects_untagged_sign1_before_key_resolution() {
    let key = gen_ed25519();
    let encoded = cose_sign1_with_options(
        key.alg,
        b"status list claims",
        &key.private,
        Some(test_kid()),
        CoseSign1EncodeOptions::new()
            .with_protected_type(CoseType::Text(STATUS_LIST_CWT_MEDIA_TYPE.to_owned())),
    )
    .expect("untagged Sign1 must encode");
    let resolver_called = Cell::new(false);
    let policy = CosePolicy::new().with_require_tagged_sign1(true);

    let error = cose_verify1_with_policy(&encoded, &policy, |_, _| {
        resolver_called.set(true);
        Some(key.public.clone())
    })
    .err()
    .expect("tag policy must reject untagged Sign1");

    assert_eq!(error, CoseError::InvalidFormat);
    assert!(!resolver_called.get());
}

#[test]
fn default_policy_preserves_untagged_compatibility() {
    let key = gen_ed25519();
    let encoded = cose_sign1_with_options(
        key.alg,
        b"ordinary claims",
        &key.private,
        Some(test_kid()),
        CoseSign1EncodeOptions::new()
            .with_protected_type(CoseType::Text("application/example+cwt".to_owned())),
    )
    .expect("untagged Sign1 must encode");

    let verified = cose_verify1_with_policy(&encoded, &CosePolicy::new(), |_, _| {
        Some(key.public.clone())
    })
    .expect("default policy must continue accepting untagged Sign1");

    assert_eq!(
        verified.cose_type,
        Some(CoseType::Text("application/example+cwt".to_owned()))
    );
}

#[test]
fn decoder_rejects_type_in_unprotected_header() {
    let key = gen_ed25519();
    let encoded = cose_sign1_with_options(
        key.alg,
        b"claims",
        &key.private,
        Some(test_kid()),
        CoseSign1EncodeOptions::default(),
    )
    .expect("fixture Sign1 must encode");
    let mut cose = CoseSign1::from_slice(&encoded).expect("fixture Sign1 must parse");
    cose.unprotected.rest.push((
        Label::Int(COSE_TYPE_HEADER_LABEL),
        Value::Text(STATUS_LIST_CWT_MEDIA_TYPE.to_owned()),
    ));
    let malformed = cose.to_vec().expect("malformed fixture must encode");

    let error = cose_verify1_with_policy(&malformed, &CosePolicy::new(), |_, _| {
        Some(key.public.clone())
    })
    .err()
    .expect("unprotected type must be rejected");

    assert_eq!(error, CoseError::UnprotectedHeaderNotAllowed);
}

#[test]
fn decoder_rejects_duplicate_type_label() {
    let protected = encode_value(&Value::Map(vec![
        (
            Value::Integer(1_i64.into()),
            Value::Integer((-8_i64).into()),
        ),
        (
            Value::Integer(COSE_TYPE_HEADER_LABEL.into()),
            Value::Text(STATUS_LIST_CWT_MEDIA_TYPE.to_owned()),
        ),
        (
            Value::Integer(COSE_TYPE_HEADER_LABEL.into()),
            Value::Integer(STATUS_LIST_CWT_CONTENT_FORMAT.into()),
        ),
    ]));
    let malformed = encode_value(&Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(Vec::new()),
        Value::Bytes(b"claims".to_vec()),
        Value::Bytes(vec![0_u8; 64]),
    ]));

    let error = cose_verify1_with_policy(&malformed, &CosePolicy::new(), |_, _| None)
        .err()
        .expect("duplicate type labels must be rejected");

    assert_eq!(error, CoseError::DuplicateMapLabel);
}

#[test]
fn decoder_rejects_negative_registered_type() {
    let protected = encode_value(&Value::Map(vec![
        (
            Value::Integer(1_i64.into()),
            Value::Integer((-8_i64).into()),
        ),
        (
            Value::Integer(COSE_TYPE_HEADER_LABEL.into()),
            Value::Integer((-1_i64).into()),
        ),
    ]));
    let malformed = encode_value(&Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(Vec::new()),
        Value::Bytes(b"claims".to_vec()),
        Value::Bytes(vec![0_u8; 64]),
    ]));

    let error = cose_verify1_with_policy(&malformed, &CosePolicy::new(), |_, _| None)
        .err()
        .expect("negative type identifiers must be rejected");

    assert_eq!(error, CoseError::InvalidFormat);
}

#[test]
fn decoder_rejects_empty_and_oversized_text_type() {
    for (text, expected) in [
        (String::new(), CoseError::InvalidFormat),
        (
            "x".repeat(MAX_COSE_TYPE_TEXT_BYTES + 1),
            CoseError::ResourceLimitExceeded,
        ),
    ] {
        let protected = encode_value(&Value::Map(vec![(
            Value::Integer(COSE_TYPE_HEADER_LABEL.into()),
            Value::Text(text),
        )]));
        let malformed = encode_value(&Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(Vec::new()),
            Value::Bytes(b"claims".to_vec()),
            Value::Bytes(vec![0_u8; 64]),
        ]));

        let error = cose_verify1_with_policy(&malformed, &CosePolicy::new(), |_, _| None)
            .err()
            .expect("invalid textual type must be rejected");
        assert_eq!(error, expected);
    }
}

#[test]
fn signer_rejects_empty_and_oversized_text_type() {
    let key = gen_ed25519();
    for (cose_type, expected) in [
        (CoseType::Text(String::new()), CoseError::InvalidFormat),
        (
            CoseType::Text("x".repeat(MAX_COSE_TYPE_TEXT_BYTES + 1)),
            CoseError::ResourceLimitExceeded,
        ),
    ] {
        let error = cose_sign1_with_options(
            key.alg,
            b"claims",
            &key.private,
            Some(test_kid()),
            CoseSign1EncodeOptions::tagged().with_protected_type(cose_type),
        )
        .expect_err("invalid textual types must be rejected");
        assert_eq!(error, expected);
    }
}

fn encode_value(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(value, &mut encoded).expect("fixture CBOR must encode");
    encoded
}
