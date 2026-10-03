// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Focused RFC 9360 x5chain encoding and limit tests.

use ciborium::value::Value;

use crate::limits::{
    MAX_COSE_X5CHAIN_CERTIFICATES, MAX_COSE_X5CHAIN_CERTIFICATE_BYTES, MAX_COSE_X5CHAIN_TOTAL_BYTES,
};
use crate::CoseError;

use super::x5chain::{decode_x5chain, protected_x5chain, validate_x5chain};

#[test]
fn rejects_single_certificate_array() {
    assert_eq!(
        decode_x5chain(&Value::Array(vec![Value::Bytes(vec![1])])),
        Err(CoseError::InvalidFormat),
    );
    assert_eq!(
        decode_x5chain(&Value::Array(Vec::new())),
        Err(CoseError::InvalidFormat),
    );
}

#[test]
fn rejects_invalid_certificate_shapes_on_decode() {
    for value in [
        Value::Bytes(Vec::new()),
        Value::Array(vec![Value::Bytes(vec![1]), Value::Bytes(Vec::new())]),
        Value::Array(vec![Value::Bytes(vec![1]), Value::Text("cert".into())]),
        Value::Text("cert".into()),
    ] {
        assert_eq!(decode_x5chain(&value), Err(CoseError::InvalidFormat));
    }
}

#[test]
fn enforces_certificate_count_before_copying_on_decode() {
    let certificates = vec![Value::Bytes(vec![1]); MAX_COSE_X5CHAIN_CERTIFICATES + 1];
    assert_eq!(
        decode_x5chain(&Value::Array(certificates)),
        Err(CoseError::ResourceLimitExceeded),
    );
}

#[test]
fn encodes_single_certificate_as_bstr() -> Result<(), CoseError> {
    let value = protected_x5chain(&[vec![1, 2, 3]]).ok_or(CoseError::InvalidFormat)?;
    assert_eq!(value, (coset::Label::Int(33), Value::Bytes(vec![1, 2, 3])));
    Ok(())
}

#[test]
fn encodes_certificate_path_as_array() -> Result<(), CoseError> {
    let value = protected_x5chain(&[vec![1], vec![2]]).ok_or(CoseError::InvalidFormat)?;
    assert_eq!(
        value,
        (
            coset::Label::Int(33),
            Value::Array(vec![Value::Bytes(vec![1]), Value::Bytes(vec![2])]),
        )
    );
    Ok(())
}

#[test]
fn rejects_empty_certificate() {
    assert_eq!(
        validate_x5chain(&[Vec::new()]),
        Err(CoseError::InvalidFormat)
    );
}

#[test]
fn rejects_certificate_count_and_size_limits() {
    let excessive_count = vec![vec![1]; MAX_COSE_X5CHAIN_CERTIFICATES + 1];
    assert_eq!(
        validate_x5chain(&excessive_count),
        Err(CoseError::ResourceLimitExceeded)
    );
    assert_eq!(
        validate_x5chain(&[vec![1; MAX_COSE_X5CHAIN_CERTIFICATE_BYTES + 1]]),
        Err(CoseError::ResourceLimitExceeded)
    );
}

#[test]
fn rejects_aggregate_size_limit() -> Result<(), CoseError> {
    let certificate_count = 5_usize;
    let Some(certificate_size) = MAX_COSE_X5CHAIN_TOTAL_BYTES
        .checked_div(certificate_count)
        .and_then(|value| value.checked_add(1))
    else {
        return Err(CoseError::InvalidFormat);
    };
    assert!(certificate_size <= MAX_COSE_X5CHAIN_CERTIFICATE_BYTES);
    let certificates = (0..certificate_count)
        .map(|index| {
            u8::try_from(index)
                .map(|byte| vec![byte; certificate_size])
                .map_err(|_| CoseError::InvalidFormat)
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        validate_x5chain(&certificates),
        Err(CoseError::ResourceLimitExceeded)
    );
    Ok(())
}
