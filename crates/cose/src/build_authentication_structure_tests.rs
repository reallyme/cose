// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;

use super::{build_authentication_structure, checked_bstr_size, AuthenticationContext};
use crate::CoseError;

#[test]
fn authentication_bstr_length_boundaries_match_independent_cbor_encoder() -> Result<(), CoseError> {
    for length in [0, 1, 23, 24, 255, 256, 65_535, 65_536] {
        let field = vec![0x44; length];
        for (context, text) in [
            (AuthenticationContext::Signature1, "Signature1"),
            (AuthenticationContext::Mac0, "MAC0"),
        ] {
            let actual = build_authentication_structure(context, &field, &field, &field)?;
            let value = Value::Array(vec![
                Value::Text(text.into()),
                Value::Bytes(field.clone()),
                Value::Bytes(field.clone()),
                Value::Bytes(field.clone()),
            ]);
            let mut expected = Vec::new();
            ciborium::ser::into_writer(&value, &mut expected).map_err(|_| CoseError::Cbor)?;
            assert_eq!(*actual, expected);
        }
    }
    Ok(())
}

#[test]
fn authentication_capacity_arithmetic_rejects_overflow() {
    assert_eq!(checked_bstr_size(usize::MAX, 0), None);
    assert_eq!(checked_bstr_size(0, usize::MAX), None);
    assert_eq!(checked_bstr_size(usize::MAX - 1, 1), None);
    assert_eq!(checked_bstr_size(0, 23), Some(24));
    assert_eq!(checked_bstr_size(0, 24), Some(26));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn complete_authentication_capacity_rejects_each_overflow_and_budget_shortfall() {
    use super::measure::authentication_structure_size;

    for lengths in [
        (usize::MAX, 0, 0, 0),
        (10, usize::MAX, 0, 0),
        (10, 0, usize::MAX, 0),
        (10, 0, 0, usize::MAX),
        (10, usize::MAX / 2, usize::MAX / 2, 0),
    ] {
        assert_eq!(
            authentication_structure_size(lengths.0, lengths.1, lengths.2, lengths.3, usize::MAX),
            Err(CoseError::ResourceLimitExceeded)
        );
    }
    assert_eq!(
        authentication_structure_size(10, 0, 0, 0, 14),
        Err(CoseError::ResourceLimitExceeded)
    );
    assert_eq!(authentication_structure_size(10, 0, 0, 0, 15), Ok(15));
}
