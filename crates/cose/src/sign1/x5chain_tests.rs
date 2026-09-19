// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Focused RFC 9360 x5chain encoding and limit tests.

use ciborium::value::Value;

use crate::limits::{
    MAX_COSE_X5CHAIN_CERTIFICATES, MAX_COSE_X5CHAIN_CERTIFICATE_BYTES, MAX_COSE_X5CHAIN_TOTAL_BYTES,
};
use crate::CoseError;

use super::x5chain::{build_unprotected_header, encode_unprotected_header, validate_x5chain};

#[test]
fn encodes_single_certificate_as_bstr() -> Result<(), CoseError> {
    let mut header = build_unprotected_header(&[vec![1, 2, 3]]);
    let value = encode_unprotected_header(&mut header)?;
    assert_eq!(
        value,
        Value::Map(vec![(
            Value::Integer(33_i64.into()),
            Value::Bytes(vec![1, 2, 3])
        )])
    );
    Ok(())
}

#[test]
fn encodes_certificate_path_as_array() -> Result<(), CoseError> {
    let mut header = build_unprotected_header(&[vec![1], vec![2]]);
    let value = encode_unprotected_header(&mut header)?;
    assert_eq!(
        value,
        Value::Map(vec![(
            Value::Integer(33_i64.into()),
            Value::Array(vec![Value::Bytes(vec![1]), Value::Bytes(vec![2])]),
        )])
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
