// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded RFC 9360 `x5chain` header encoding for COSE_Sign1.

use ciborium::value::Value;
use coset::{iana, Header, Label};

use crate::limits::{
    MAX_COSE_X5CHAIN_CERTIFICATES, MAX_COSE_X5CHAIN_CERTIFICATE_BYTES, MAX_COSE_X5CHAIN_TOTAL_BYTES,
};
use crate::CoseError;

const X5CHAIN_LABEL: i64 = iana::HeaderParameter::X5Chain as i64;

pub(super) fn validate_x5chain<B: AsRef<[u8]>>(certificates_der: &[B]) -> Result<(), CoseError> {
    if certificates_der.is_empty() {
        return Ok(());
    }
    if certificates_der.len() > MAX_COSE_X5CHAIN_CERTIFICATES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let mut total_bytes = 0_usize;
    for certificate_der in certificates_der {
        let certificate_der = certificate_der.as_ref();
        if certificate_der.is_empty() {
            return Err(CoseError::InvalidFormat);
        }
        if certificate_der.len() > MAX_COSE_X5CHAIN_CERTIFICATE_BYTES {
            return Err(CoseError::ResourceLimitExceeded);
        }
        total_bytes = total_bytes
            .checked_add(certificate_der.len())
            .ok_or(CoseError::ResourceLimitExceeded)?;
        if total_bytes > MAX_COSE_X5CHAIN_TOTAL_BYTES {
            return Err(CoseError::ResourceLimitExceeded);
        }
    }
    Ok(())
}

pub(super) fn x5chain_header<B: AsRef<[u8]>>(certificates_der: &[B]) -> Option<(Label, Value)> {
    if certificates_der.is_empty() {
        return None;
    }
    let value = if certificates_der.len() == 1 {
        Value::Bytes(certificates_der[0].as_ref().to_vec())
    } else {
        Value::Array(
            certificates_der
                .iter()
                .map(|value| Value::Bytes(value.as_ref().to_vec()))
                .collect(),
        )
    };
    Some((Label::Int(X5CHAIN_LABEL), value))
}

pub(super) fn decode_x5chain(value: &Value) -> Result<Vec<Vec<u8>>, CoseError> {
    // Validate the complete borrowed chain before copying any certificate.
    // A malformed later entry must not strand earlier copies on an error path.
    validate_x5chain_value(value)?;
    match value {
        Value::Bytes(certificate) => Ok(vec![certificate.clone()]),
        Value::Array(values) => values
            .iter()
            .map(|value| match value {
                Value::Bytes(certificate) => Ok(certificate.clone()),
                _ => Err(CoseError::InvalidFormat),
            })
            .collect(),
        _ => Err(CoseError::InvalidFormat),
    }
}

pub(crate) fn validate_x5chain_value(value: &Value) -> Result<(), CoseError> {
    match value {
        Value::Bytes(certificate) => validate_certificate_size(certificate),
        Value::Array(values) => {
            if values.len() < 2 {
                return Err(CoseError::InvalidFormat);
            }
            if values.len() > MAX_COSE_X5CHAIN_CERTIFICATES {
                return Err(CoseError::ResourceLimitExceeded);
            }
            let mut total = 0_usize;
            for value in values {
                let Value::Bytes(certificate) = value else {
                    return Err(CoseError::InvalidFormat);
                };
                validate_certificate_size(certificate)?;
                total = total
                    .checked_add(certificate.len())
                    .ok_or(CoseError::ResourceLimitExceeded)?;
                if total > MAX_COSE_X5CHAIN_TOTAL_BYTES {
                    return Err(CoseError::ResourceLimitExceeded);
                }
            }
            Ok(())
        }
        _ => Err(CoseError::InvalidFormat),
    }
}

pub(crate) fn validate_certificate_size(certificate: &[u8]) -> Result<(), CoseError> {
    if certificate.is_empty() {
        return Err(CoseError::InvalidFormat);
    }
    if certificate.len() > MAX_COSE_X5CHAIN_CERTIFICATE_BYTES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    Ok(())
}

pub(super) fn encode_unprotected_header(header: &mut Header) -> Result<Value, CoseError> {
    if header.rest.is_empty() {
        return Ok(Value::Map(Vec::new()));
    }
    if header.rest.len() != 1 {
        return Err(CoseError::InvalidFormat);
    }
    let (label, value) = header.rest.pop().ok_or(CoseError::InvalidFormat)?;
    if label != Label::Int(X5CHAIN_LABEL) {
        return Err(CoseError::InvalidFormat);
    }
    Ok(Value::Map(vec![(
        Value::Integer(X5CHAIN_LABEL.into()),
        value,
    )]))
}
