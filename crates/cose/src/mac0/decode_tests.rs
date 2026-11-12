// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use zeroize::Zeroizing;

use crate::mac0::{
    cose_verify_mac0_detached, CoseMac0Error, CoseMac0ErrorReason, CoseMacAlgorithm, CoseMacKey,
};

use super::support::{assert_reason, detached, encode, envelope, hex, request, tag, verify};

#[test]
fn content_type_values_are_validated_in_both_buckets() -> Result<(), CoseMac0Error> {
    for value in [
        Value::from(0),
        Value::Text("application/cbor".into()),
        Value::Text("application/vnd.example+json".into()),
    ] {
        let protected = encode(Value::Map(vec![(1.into(), 5.into()), (3.into(), value)]));
        verify(&detached(&protected, &tag(&protected, b"payload", b"aad")))?;
    }
    for value in [
        Value::Null,
        Value::from(-1),
        Value::Text("".into()),
        Value::Text("cbor".into()),
        Value::Text(" application/cbor".into()),
        Value::Text("application/cbor; charset=utf-8".into()),
        Value::Text("app/*".into()),
        Value::Text("app/a/b".into()),
    ] {
        let protected = encode(Value::Map(vec![
            (1.into(), 5.into()),
            (3.into(), value.clone()),
        ]));
        assert_reason(
            verify(&detached(&protected, &[0; 32])),
            CoseMac0ErrorReason::InvalidStructure,
        );
        let encoded = envelope(
            &hex("a10105"),
            Value::Map(vec![(3.into(), value)]),
            Value::Null,
            &[0; 32],
        );
        assert_reason(verify(&encoded), CoseMac0ErrorReason::InvalidStructure);
    }
    Ok(())
}

#[test]
fn malformed_top_level_shapes_and_trailing_data_are_rejected() {
    for (bytes, reason) in [
        ("", CoseMac0ErrorReason::MalformedCbor),
        ("00", CoseMac0ErrorReason::InvalidStructure),
        ("a0", CoseMac0ErrorReason::InvalidStructure),
        ("83", CoseMac0ErrorReason::InvalidStructure),
        ("85", CoseMac0ErrorReason::InvalidStructure),
        ("8480a0f65820", CoseMac0ErrorReason::MalformedCbor),
        ("8443a1010580f640", CoseMac0ErrorReason::InvalidStructure),
        ("8443a10105a0f6f6", CoseMac0ErrorReason::InvalidStructure),
    ] {
        assert_reason(verify(&hex(bytes)), reason);
    }
    let valid_shape = detached(&hex("a10105"), &[0; 32]);
    for end in 0..valid_shape.len() {
        assert_reason(
            verify(&valid_shape[..end]),
            CoseMac0ErrorReason::MalformedCbor,
        );
    }
    let mut trailing = valid_shape.clone();
    trailing.push(0);
    assert_reason(verify(&trailing), CoseMac0ErrorReason::MalformedCbor);
    for tag in [0xc0, 0xd0, 0xd2] {
        let mut tagged = vec![tag];
        tagged.extend_from_slice(&valid_shape);
        assert_reason(verify(&tagged), CoseMac0ErrorReason::UnexpectedTag);
    }
    let mut double_tag = vec![0xd1, 0xd1];
    double_tag.extend_from_slice(&valid_shape);
    assert_reason(verify(&double_tag), CoseMac0ErrorReason::InvalidStructure);
}

#[test]
fn duplicate_and_conflicting_headers_are_rejected_in_each_bucket() {
    for protected in ["a201050105", "a30105044161044162", "a30105617800617801"] {
        assert_reason(
            verify(&detached(&hex(protected), &[0; 32])),
            CoseMac0ErrorReason::DuplicateHeader,
        );
    }
    let protected = hex("a10105");
    let unprotected = Value::Map(vec![
        (4.into(), Value::Bytes(vec![1])),
        (4.into(), Value::Bytes(vec![2])),
    ]);
    assert_reason(
        verify(&envelope(&protected, unprotected, Value::Null, &[0; 32])),
        CoseMac0ErrorReason::DuplicateHeader,
    );
    for (protected_hex, label, value) in [
        ("a10105", Value::from(1), Value::from(5)),
        ("a10105", Value::from(1), Value::from(6)),
        ("a20105044161", Value::from(4), Value::Bytes(vec![1])),
        ("a20105617800", Value::Text("x".into()), Value::from(1)),
    ] {
        let encoded = envelope(
            &hex(protected_hex),
            Value::Map(vec![(label, value)]),
            Value::Null,
            &[0; 32],
        );
        assert_reason(verify(&encoded), CoseMac0ErrorReason::DuplicateHeader);
    }
}

#[test]
fn malformed_protected_headers_and_missing_algorithms_fail_closed() {
    for protected in ["", "a0", "a1044161"] {
        assert_reason(
            verify(&detached(&hex(protected), &[0; 32])),
            CoseMac0ErrorReason::MissingProtectedAlgorithm,
        );
    }
    for (protected, reason) in [
        ("00", CoseMac0ErrorReason::InvalidStructure),
        ("80", CoseMac0ErrorReason::InvalidStructure),
        ("a10105ff", CoseMac0ErrorReason::MalformedCbor),
        ("a1f605", CoseMac0ErrorReason::InvalidStructure),
        ("a101f6", CoseMac0ErrorReason::UnsupportedAlgorithm),
        ("a201050401", CoseMac0ErrorReason::InvalidStructure),
    ] {
        assert_reason(verify(&detached(&hex(protected), &[0; 32])), reason);
    }
    for protected in [
        "a1010f",
        "a10126",
        "a101654853323536",
        "a1011bffffffffffffffff",
    ] {
        assert_reason(
            verify(&detached(&hex(protected), &[0; 32])),
            CoseMac0ErrorReason::UnsupportedAlgorithm,
        );
    }
    for protected in ["a1180105", "a1011805", "bf0105ff"] {
        assert_reason(
            verify(&detached(&hex(protected), &[0; 32])),
            CoseMac0ErrorReason::NonCanonicalCbor,
        );
    }
    // Undefined must never be collapsed to the null required for detachment.
    let mut undefined = detached(&hex("a10105"), &[0; 32]);
    undefined[6] = 0xf7;
    assert_reason(verify(&undefined), CoseMac0ErrorReason::MalformedCbor);
}

#[test]
fn critical_headers_are_protected_present_unique_nonempty_and_understood() {
    for protected in ["a201050280", "a201050201", "a20105028104", "a20105028180"] {
        assert_reason(
            verify(&detached(&hex(protected), &[0; 32])),
            CoseMac0ErrorReason::InvalidStructure,
        );
    }
    assert_reason(
        verify(&detached(&hex("a2010502820101"), &[0; 32])),
        CoseMac0ErrorReason::DuplicateHeader,
    );
    for protected in [
        "a301050281182a182a00",
        "a3010502816178617800",
        "a20105028102",
    ] {
        assert_reason(
            verify(&detached(&hex(protected), &[0; 32])),
            CoseMac0ErrorReason::UnsupportedCriticalHeader,
        );
    }
    for (label, value) in [
        (1.into(), 5.into()),
        (2.into(), Value::Array(vec![1.into()])),
    ] {
        let encoded = envelope(
            &hex("a1044161"),
            Value::Map(vec![(label, value)]),
            Value::Null,
            &[0; 32],
        );
        assert_reason(
            verify(&encoded),
            CoseMac0ErrorReason::UnprotectedSecurityHeader,
        );
    }
}

#[test]
fn hmac_rejects_iv_and_countersignature_semantics() {
    for protected in ["a201050540", "a201050640", "a201050780", "a3010505400640"] {
        assert_reason(
            verify(&detached(&hex(protected), &[0; 32])),
            CoseMac0ErrorReason::InvalidStructure,
        );
    }
}

#[test]
fn exact_tag_lengths_are_required_for_every_algorithm() -> Result<(), CoseMac0Error> {
    for algorithm in [
        CoseMacAlgorithm::Hmac256_64,
        CoseMacAlgorithm::Hmac256_256,
        CoseMacAlgorithm::Hmac384_384,
        CoseMacAlgorithm::Hmac512_512,
    ] {
        let key = CoseMacKey::new(
            algorithm,
            Zeroizing::new(vec![0x11; algorithm.key_length()]),
        )?;
        let protected = encode(Value::Map(vec![(1.into(), algorithm.cose_id().into())]));
        for length in [
            0,
            1,
            algorithm.tag_length() - 1,
            algorithm.tag_length() + 1,
            65,
        ] {
            let encoded = detached(&protected, &vec![0; length]);
            let mut input = request(&encoded, &[], &[]);
            input.allowed_algorithms = std::slice::from_ref(&algorithm);
            assert_reason(
                cose_verify_mac0_detached(input, &key),
                CoseMac0ErrorReason::InvalidTagLength,
            );
        }
    }
    Ok(())
}
