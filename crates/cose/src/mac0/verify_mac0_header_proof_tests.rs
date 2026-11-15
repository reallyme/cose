// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::mem::ManuallyDrop;

use ciborium::Value;

use super::{validate_headers, CoseMac0Error, CoseMac0ErrorReason, CoseMacAlgorithm, HeaderEntry};

#[kani::proof]
fn mac0_wire_algorithm_ids_select_only_exact_supported_registrations() {
    let id: i64 = kani::any();
    let expected = match id {
        4 => Some(CoseMacAlgorithm::Hmac256_64),
        5 => Some(CoseMacAlgorithm::Hmac256_256),
        6 => Some(CoseMacAlgorithm::Hmac384_384),
        7 => Some(CoseMacAlgorithm::Hmac512_512),
        _ => None,
    };
    let actual = CoseMacAlgorithm::from_cose_id(id);
    match (actual, expected) {
        (Ok(algorithm), Some(expected)) => {
            assert!(algorithm == expected && algorithm.cose_id() == id);
        }
        (Err(error), None) => {
            assert!(error.reason() == CoseMac0ErrorReason::UnsupportedAlgorithm);
        }
        _ => {
            assert!(
                false,
                "the wire ID must resolve to its exact MAC registration"
            );
        }
    }
    kani::cover!(id == 4, "truncated HMAC-SHA256 is selected");
    kani::cover!(id == 5, "full HMAC-SHA256 is selected");
    kani::cover!(id == i64::MIN, "unsupported identifiers fail closed");
}

#[kani::proof]
#[kani::unwind(12)]
#[kani::stub(super::validate_header_placement, validate_fixture_placement)]
#[kani::stub(super::validate_common_value, validate_fixture_value)]
#[kani::stub(super::validate_critical, reject_fixture_critical)]
fn mac0_unprotected_kid_cannot_be_authenticated_metadata() {
    let protected_kid: u8 = kani::any();
    let unprotected_kid: u8 = kani::any();
    let has_protected_kid: bool = kani::any();
    let has_unprotected_kid: bool = kani::any();
    let protected = ManuallyDrop::new([
        (Value::Integer(4.into()), Value::Bytes(vec![protected_kid])),
        (Value::Integer(1.into()), Value::Integer(4.into())),
    ]);
    let unprotected = ManuallyDrop::new([(
        Value::Integer(4.into()),
        Value::Bytes(vec![unprotected_kid]),
    )]);
    let actual = validate_headers(
        &protected[usize::from(!has_protected_kid)..],
        &unprotected[..usize::from(has_unprotected_kid)],
    );
    if has_protected_kid && has_unprotected_kid {
        assert!(
            matches!(actual, Err(error) if error.reason() == CoseMac0ErrorReason::DuplicateHeader)
        );
    } else {
        let expected = [protected_kid];
        assert!(
            matches!(actual, Ok((algorithm, kid)) if algorithm == CoseMacAlgorithm::Hmac256_64 && kid == has_protected_kid.then_some(expected.as_slice()))
        );
    }
    kani::cover!(
        !has_protected_kid && has_unprotected_kid,
        "an unprotected kid contributes no authenticated metadata"
    );
    kani::cover!(
        has_protected_kid && !has_unprotected_kid,
        "the protected kid is preserved"
    );
    kani::cover!(
        has_protected_kid && has_unprotected_kid && protected_kid != unprotected_kid,
        "a duplicate kid is rejected"
    );
}

// The native duplicate-header vectors exercise placement. In this proof,
// model its result so the metadata projection can be checked independently.
#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn validate_fixture_placement(
    protected: &[HeaderEntry],
    unprotected: &[HeaderEntry],
) -> Result<(), CoseMac0Error> {
    assert!(matches!(protected.len(), 1 | 2) && unprotected.len() <= 1);
    if protected.len() == 2 && unprotected.len() == 1 {
        Err(CoseMac0ErrorReason::DuplicateHeader.into())
    } else {
        Ok(())
    }
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn validate_fixture_value(label: &Value, value: &Value) -> Result<(), CoseMac0Error> {
    assert!(match label.as_integer().map(i128::from) {
        Some(1) => value.as_integer() == Some(4.into()),
        Some(4) => value.as_bytes().is_some_and(|bytes| bytes.len() == 1),
        _ => false,
    });
    Ok(())
}

#[allow(dead_code, reason = "Kani resolves stubs after Rust linting")]
fn reject_fixture_critical(
    _value: &Value,
    _protected: &[HeaderEntry],
) -> Result<(), CoseMac0Error> {
    assert!(false, "the fixture has no critical labels");
    Err(CoseMac0ErrorReason::UnsupportedCriticalHeader.into())
}
