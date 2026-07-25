// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Bounded COSE_Sign1 decoding and structural validation.

use ciborium::value::Value;
use coset::{iana, AsCborValue, CoseSign1, Header, ProtectedHeader, RegisteredLabelWithPrivate};

use crate::limits::validate_protected_header_bytes;
use crate::zeroize_coset::{zeroize_cose_sign1, SensitiveCborValue};
use crate::CoseError;

/// Decode untagged COSE_Sign1 bytes, or bytes carrying the registered
/// COSE_Sign1 tag (18) already allowed by the byte-boundary tag policy.
pub(super) fn decode_cose_sign1(
    cose_bytes: &[u8],
    max_len: usize,
) -> Result<SensitiveCoseSign1, CoseError> {
    let decoded = SensitiveCborValue::decode_cose_sign1(cose_bytes, max_len)?;
    let body = match decoded.value() {
        Value::Tag(18, body) => body.as_ref(),
        value => value,
    };
    let items = match body {
        Value::Array(items) => items,
        _ => return Err(CoseError::InvalidFormat),
    };
    let [protected_value, unprotected_value, payload_value, signature_value] = items.as_slice()
    else {
        return Err(CoseError::InvalidFormat);
    };

    // Establish the recursive wipe owner before cloning any semantic field.
    // Every rejected header or field type below therefore clears both the
    // original CBOR tree and the partially constructed COSE object.
    let mut cose = SensitiveCoseSign1::new(CoseSign1::default());
    decode_protected_header(protected_value, &mut cose.inner_mut().protected)?;
    decode_sign1_header(
        unprotected_value,
        &mut cose.inner_mut().unprotected,
        Sign1HeaderBucket::Unprotected,
    )?;
    cose.inner_mut().payload = match payload_value {
        Value::Bytes(payload) => Some(payload.clone()),
        Value::Null => None,
        _ => return Err(CoseError::InvalidFormat),
    };
    cose.inner_mut().signature = match signature_value {
        Value::Bytes(signature) => signature.clone(),
        _ => return Err(CoseError::InvalidSignatureEncoding),
    };
    Ok(cose)
}

#[derive(Clone, Copy)]
enum Sign1HeaderBucket {
    Protected,
    Unprotected,
}

fn decode_protected_header(
    value: &Value,
    protected: &mut ProtectedHeader,
) -> Result<(), CoseError> {
    let bytes = match value {
        Value::Bytes(bytes) => bytes,
        _ => return Err(CoseError::InvalidFormat),
    };
    protected.original_data = Some(bytes.clone());
    if bytes.is_empty() {
        return Ok(());
    }

    let decoded = SensitiveCborValue::decode_protected_header(bytes)?;
    decode_sign1_header(
        decoded.value(),
        &mut protected.header,
        Sign1HeaderBucket::Protected,
    )
}

fn decode_sign1_header(
    value: &Value,
    header: &mut Header,
    bucket: Sign1HeaderBucket,
) -> Result<(), CoseError> {
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err(CoseError::InvalidFormat),
    };
    let mut saw_algorithm = false;
    let mut saw_kid = false;

    for (label, value) in entries {
        let label = match label {
            Value::Integer(integer) => {
                i64::try_from(*integer).map_err(|_| CoseError::InvalidFormat)?
            }
            Value::Text(_) => return Err(CoseError::InvalidFormat),
            _ => return Err(CoseError::InvalidFormat),
        };
        if label == iana::HeaderParameter::Alg as i64 {
            if saw_algorithm {
                return Err(CoseError::DuplicateMapLabel);
            }
            saw_algorithm = true;
            if matches!(bucket, Sign1HeaderBucket::Unprotected) {
                return Err(CoseError::UnprotectedHeaderNotAllowed);
            }
            header.alg = Some(parse_header_algorithm(value)?);
        } else if label == iana::HeaderParameter::Kid as i64 {
            if saw_kid {
                return Err(CoseError::DuplicateMapLabel);
            }
            saw_kid = true;
            if matches!(bucket, Sign1HeaderBucket::Unprotected) {
                return Err(CoseError::UnprotectedHeaderNotAllowed);
            }
            header.key_id = match value {
                Value::Bytes(kid) if !kid.is_empty() => kid.clone(),
                _ => return Err(CoseError::InvalidFormat),
            };
        } else if label == iana::HeaderParameter::Crit as i64 {
            return Err(CoseError::UnsupportedCriticalHeader);
        } else {
            // This SDK does not expose processing results for content-type,
            // countersignatures, extension headers, or application-specific
            // unprotected metadata. Accepting them would imply semantics that
            // the returned verified result cannot represent.
            return Err(CoseError::InvalidFormat);
        }
    }
    Ok(())
}

fn parse_header_algorithm(
    value: &Value,
) -> Result<RegisteredLabelWithPrivate<iana::Algorithm>, CoseError> {
    match value {
        Value::Integer(integer) => {
            RegisteredLabelWithPrivate::from_cbor_value(Value::Integer(*integer))
                .map_err(|_| CoseError::InvalidFormat)
        }
        Value::Text(text) => Ok(RegisteredLabelWithPrivate::Text(text.clone())),
        _ => Err(CoseError::InvalidFormat),
    }
}

pub(super) struct SensitiveCoseSign1 {
    inner: CoseSign1,
}

impl SensitiveCoseSign1 {
    fn new(inner: CoseSign1) -> Self {
        Self { inner }
    }

    pub(super) fn inner(&self) -> &CoseSign1 {
        &self.inner
    }

    pub(super) fn inner_mut(&mut self) -> &mut CoseSign1 {
        &mut self.inner
    }
}

impl Drop for SensitiveCoseSign1 {
    fn drop(&mut self) {
        zeroize_cose_sign1(&mut self.inner);
    }
}

pub(super) fn validate_cose_sign1_structure(cose: &CoseSign1) -> Result<(), CoseError> {
    if let Some(protected_bytes) = &cose.protected.original_data {
        validate_protected_header_bytes(protected_bytes)?;
    }

    if !cose.protected.header.crit.is_empty() {
        return Err(CoseError::UnsupportedCriticalHeader);
    }

    if cose.unprotected.alg.is_some() || !cose.unprotected.key_id.is_empty() {
        return Err(CoseError::UnprotectedHeaderNotAllowed);
    }

    if !cose.unprotected.crit.is_empty() {
        return Err(CoseError::UnsupportedCriticalHeader);
    }

    Ok(())
}
