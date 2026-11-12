// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;

use super::{CoseMac0Error, CoseMac0ErrorReason, CoseMacAlgorithm};

const ALGORITHM_LABEL: i64 = 1;
const CRITICAL_LABEL: i64 = 2;
const CONTENT_TYPE_LABEL: i64 = 3;
const KEY_ID_LABEL: i64 = 4;
const IV_LABEL: i64 = 5;
const PARTIAL_IV_LABEL: i64 = 6;
const COUNTER_SIGNATURE_LABEL: i64 = 7;
const MAX_MEDIA_TYPE_NAME_BYTES: usize = 127;

type HeaderEntry = (Value, Value);

pub(super) fn validate_headers<'a>(
    protected: &'a [HeaderEntry],
    unprotected: &[HeaderEntry],
) -> Result<(CoseMacAlgorithm, Option<&'a [u8]>), CoseMac0Error> {
    // Compare semantic labels across buckets as well as the raw duplicate
    // checks in preflight. No unprotected value may shadow protected metadata.
    for (label, _) in protected {
        validate_label(label)?;
        if unprotected.iter().any(|(other, _)| label == other) {
            return Err(CoseMac0ErrorReason::DuplicateHeader.into());
        }
    }
    for (label, value) in unprotected {
        validate_label(label)?;
        if matches!(integer_label(label), Some(ALGORITHM_LABEL | CRITICAL_LABEL)) {
            return Err(CoseMac0ErrorReason::UnprotectedSecurityHeader.into());
        }
        validate_common_value(label, value)?;
    }

    let mut algorithm = None;
    let mut kid = None;
    for (label, value) in protected {
        validate_common_value(label, value)?;
        match integer_label(label) {
            Some(ALGORITHM_LABEL) => {
                let Value::Integer(id) = value else {
                    return Err(CoseMac0ErrorReason::UnsupportedAlgorithm.into());
                };
                let id =
                    i64::try_from(*id).map_err(|_| CoseMac0ErrorReason::UnsupportedAlgorithm)?;
                algorithm = Some(CoseMacAlgorithm::from_cose_id(id)?);
            }
            Some(KEY_ID_LABEL) => {
                let Value::Bytes(bytes) = value else {
                    return Err(CoseMac0ErrorReason::InvalidStructure.into());
                };
                kid = Some(bytes.as_slice());
            }
            Some(CRITICAL_LABEL) => validate_critical(value, protected)?,
            _ => {}
        }
    }

    Ok((
        algorithm.ok_or(CoseMac0ErrorReason::MissingProtectedAlgorithm)?,
        kid,
    ))
}

fn validate_label(label: &Value) -> Result<(), CoseMac0Error> {
    match label {
        Value::Integer(integer) if i64::try_from(*integer).is_ok() => Ok(()),
        Value::Text(_) => Ok(()),
        _ => Err(CoseMac0ErrorReason::InvalidStructure.into()),
    }
}

fn integer_label(label: &Value) -> Option<i64> {
    match label {
        Value::Integer(integer) => i64::try_from(*integer).ok(),
        _ => None,
    }
}

fn validate_common_value(label: &Value, value: &Value) -> Result<(), CoseMac0Error> {
    match integer_label(label) {
        Some(KEY_ID_LABEL) if !matches!(value, Value::Bytes(_)) => {
            Err(CoseMac0ErrorReason::InvalidStructure.into())
        }
        Some(CONTENT_TYPE_LABEL) => match value {
            Value::Integer(integer) if u64::try_from(*integer).is_ok() => Ok(()),
            Value::Text(text) if valid_media_type(text) => Ok(()),
            _ => Err(CoseMac0ErrorReason::InvalidStructure.into()),
        },
        // HMAC has no IV, and this profile does not process countersignatures.
        // Accepting these would suggest security semantics it cannot enforce.
        Some(IV_LABEL | PARTIAL_IV_LABEL | COUNTER_SIGNATURE_LABEL) => {
            Err(CoseMac0ErrorReason::InvalidStructure.into())
        }
        _ => Ok(()),
    }
}

fn valid_media_type(text: &str) -> bool {
    // RFC 9052 uses the restricted RFC 6838 type/subtype syntax here. This
    // profile accepts bare media types, without MIME parameters or wildcards.
    let Some((kind, subtype)) = text.split_once('/') else {
        return false;
    };
    [kind, subtype].into_iter().all(|name| {
        !name.is_empty()
            && name.len() <= MAX_MEDIA_TYPE_NAME_BYTES
            && name
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+'
                    )
            })
    })
}

fn validate_critical(value: &Value, protected: &[HeaderEntry]) -> Result<(), CoseMac0Error> {
    let Value::Array(labels) = value else {
        return Err(CoseMac0ErrorReason::InvalidStructure.into());
    };
    if labels.is_empty() {
        return Err(CoseMac0ErrorReason::InvalidStructure.into());
    }
    for (index, label) in labels.iter().enumerate() {
        validate_label(label)?;
        if labels.iter().take(index).any(|previous| previous == label) {
            return Err(CoseMac0ErrorReason::DuplicateHeader.into());
        }
        if !protected.iter().any(|(present, _)| present == label) {
            return Err(CoseMac0ErrorReason::InvalidStructure.into());
        }
        // Only these fields have enforced semantics and corresponding typed
        // results. Merely preserving an extension's bytes is not understanding it.
        if !matches!(integer_label(label), Some(ALGORITHM_LABEL | KEY_ID_LABEL)) {
            return Err(CoseMac0ErrorReason::UnsupportedCriticalHeader.into());
        }
    }
    Ok(())
}
