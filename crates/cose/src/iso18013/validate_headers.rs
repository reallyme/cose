// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::sign1::validate_x5chain_value;
use crate::CoseError;
use ciborium::value::Value;

use super::Iso18013SignatureAlgorithm;

const ALGORITHM_LABEL: i64 = 1;
const CRITICAL_LABEL: i64 = 2;
const CONTENT_TYPE_LABEL: i64 = 3;
const KEY_ID_LABEL: i64 = 4;
const X5CHAIN_LABEL: i64 = 33;
const IV_LABEL: i64 = 5;
const PARTIAL_IV_LABEL: i64 = 6;
const COUNTER_SIGNATURE_LABELS: [i64; 4] = [7, 9, 11, 12];
const MAX_MEDIA_TYPE_NAME_BYTES: usize = 127;
type HeaderEntry = (Value, Value);

pub(super) fn validate<'a>(
    protected: &'a [HeaderEntry],
    unprotected: &[HeaderEntry],
) -> Result<(Iso18013SignatureAlgorithm, Option<&'a [u8]>), CoseError> {
    for (label, _) in protected {
        validate_label(label)?;
        if unprotected.iter().any(|(other, _)| label == other) {
            return Err(CoseError::DuplicateMapLabel);
        }
    }
    let mut algorithm = None;
    let mut kid = None;
    for (label, value) in protected {
        validate_value(label, value)?;
        match integer_label(label) {
            Some(ALGORITHM_LABEL) => {
                let Value::Integer(identifier) = value else {
                    return Err(CoseError::UnsupportedAlgorithm);
                };
                let identifier =
                    i64::try_from(*identifier).map_err(|_| CoseError::UnsupportedAlgorithm)?;
                algorithm = Some(Iso18013SignatureAlgorithm::from_identifier(identifier)?);
            }
            Some(KEY_ID_LABEL) => {
                let Value::Bytes(bytes) = value else {
                    return Err(CoseError::InvalidFormat);
                };
                kid = Some(bytes.as_slice());
            }
            _ => {}
        }
    }
    for (label, value) in unprotected {
        validate_label(label)?;
        if integer_label(label) == Some(ALGORITHM_LABEL) {
            return Err(CoseError::UnprotectedHeaderNotAllowed);
        }
        validate_value(label, value)?;
    }
    Ok((algorithm.ok_or(CoseError::UnsupportedAlgorithm)?, kid))
}

fn validate_label(label: &Value) -> Result<(), CoseError> {
    match label {
        Value::Integer(integer) if i64::try_from(*integer).is_ok() => Ok(()),
        Value::Text(_) => Ok(()),
        _ => Err(CoseError::InvalidFormat),
    }
}

fn integer_label(label: &Value) -> Option<i64> {
    match label {
        Value::Integer(integer) => i64::try_from(*integer).ok(),
        _ => None,
    }
}

fn validate_value(label: &Value, value: &Value) -> Result<(), CoseError> {
    match integer_label(label) {
        Some(CRITICAL_LABEL) => Err(CoseError::UnsupportedCriticalHeader),
        Some(CONTENT_TYPE_LABEL) => validate_content_type(value),
        Some(KEY_ID_LABEL) if !matches!(value, Value::Bytes(_)) => Err(CoseError::InvalidFormat),
        Some(IV_LABEL | PARTIAL_IV_LABEL) => Err(CoseError::InvalidFormat),
        Some(label) if COUNTER_SIGNATURE_LABELS.contains(&label) => Err(CoseError::InvalidFormat),
        Some(X5CHAIN_LABEL) => {
            // The shared validator borrows the existing wipe tree; certificate
            // trust is not a consequence of successful signature verification.
            validate_x5chain_value(value)
        }
        _ => Ok(()),
    }
}

fn validate_content_type(value: &Value) -> Result<(), CoseError> {
    match value {
        Value::Integer(integer) if u64::try_from(*integer).is_ok() => Ok(()),
        Value::Text(text) => {
            let Some((kind, subtype)) = text.split_once('/') else {
                return Err(CoseError::InvalidFormat);
            };
            // This profile accepts bare RFC 6838 media types. Parameters and
            // application content interpretation require a separate policy.
            let valid = [kind, subtype].into_iter().all(|name| {
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
            });
            if valid {
                Ok(())
            } else {
                Err(CoseError::InvalidFormat)
            }
        }
        _ => Err(CoseError::InvalidFormat),
    }
}
