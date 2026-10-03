// SPDX-FileCopyrightText: 2026 ReallyMe LLC
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

pub(super) fn validate_x5chain(certificates_der: &[Vec<u8>]) -> Result<(), CoseError> {
    if certificates_der.is_empty() {
        return Ok(());
    }
    if certificates_der.len() > MAX_COSE_X5CHAIN_CERTIFICATES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let mut total_bytes = 0_usize;
    for certificate_der in certificates_der {
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

pub(super) fn protected_x5chain(certificates_der: &[Vec<u8>]) -> Option<(Label, Value)> {
    if certificates_der.is_empty() {
        return None;
    }
    let value = if certificates_der.len() == 1 {
        Value::Bytes(certificates_der[0].clone())
    } else {
        Value::Array(certificates_der.iter().cloned().map(Value::Bytes).collect())
    };
    Some((Label::Int(X5CHAIN_LABEL), value))
}

pub(super) fn decode_x5chain(value: &Value) -> Result<Vec<Vec<u8>>, CoseError> {
    let certificates = match value {
        Value::Bytes(certificate) => {
            validate_certificate_size(certificate)?;
            vec![certificate.clone()]
        }
        Value::Array(values) => {
            if values.len() < 2 {
                return Err(CoseError::InvalidFormat);
            }
            if values.len() > MAX_COSE_X5CHAIN_CERTIFICATES {
                return Err(CoseError::ResourceLimitExceeded);
            }
            let mut total = 0_usize;
            let mut certificates = Vec::with_capacity(values.len());
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
                certificates.push(certificate.clone());
            }
            certificates
        }
        _ => return Err(CoseError::InvalidFormat),
    };
    validate_x5chain(&certificates)?;
    if certificates.is_empty() {
        return Err(CoseError::InvalidFormat);
    }
    Ok(certificates)
}

fn validate_certificate_size(certificate: &[u8]) -> Result<(), CoseError> {
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
