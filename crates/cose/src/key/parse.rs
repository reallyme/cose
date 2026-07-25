// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Operation-specific COSE_Key parsing semantics.

use ciborium::value::Value;
use coset::{iana, AsCborValue, Label, RegisteredLabel, RegisteredLabelWithPrivate};
use zeroize::Zeroize;

use crate::failure::CoseFailure;
use crate::zeroize_coset::SensitiveCborValue;
use crate::{CoseError, CoseKey};

use super::profile::validate_parsed_cose_key;

/// Borrowed domain input for the COSE_Key parse operation.
pub(crate) struct CoseKeyParseInput<'a> {
    encoded: &'a [u8],
}

impl<'a> CoseKeyParseInput<'a> {
    pub(crate) const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded }
    }
}

/// Owning domain output for the COSE_Key parse operation.
///
/// Keeping the key behind an operation-specific owner prevents adapters from
/// treating arbitrary result bytes as an interchangeable semantic result.
#[must_use]
pub(crate) struct CoseKeyParseOutput {
    key: CoseKey,
}

impl CoseKeyParseOutput {
    pub(crate) fn into_key(self) -> CoseKey {
        self.key
    }
}

/// Parses and validates one canonical, untagged COSE_Key.
///
/// This function accepts only domain input. Transport decoding, generated
/// protobuf ownership, and result serialization remain adapter concerns.
pub(crate) fn parse_cose_key(
    input: CoseKeyParseInput<'_>,
) -> Result<CoseKeyParseOutput, CoseFailure> {
    let key = decode_owned_cose_key(input.encoded).map_err(CoseFailure::from)?;
    validate_parsed_cose_key(&key).map_err(CoseFailure::from)?;
    Ok(CoseKeyParseOutput { key })
}

/// Decode a COSE_Key from canonical, untagged CBOR bytes.
///
/// # Errors
///
/// Returns [`CoseError`] when the CBOR is malformed, non-canonical, oversized,
/// tagged, duplicated, or does not satisfy the supported COSE_Key profiles.
pub fn cose_key_from_slice(bytes: &[u8]) -> Result<CoseKey, CoseError> {
    parse_cose_key(CoseKeyParseInput::new(bytes))
        .map(CoseKeyParseOutput::into_key)
        .map_err(CoseFailure::into_native_error)
}

fn decode_owned_cose_key(bytes: &[u8]) -> Result<CoseKey, CoseError> {
    let mut decoded = SensitiveCborValue::decode_cose_key(bytes)?;
    let entries = match decoded.value_mut() {
        Value::Map(entries) => entries,
        _ => return Err(CoseError::Cbor),
    };

    // Establish the destination wipe owner before moving any decoded field.
    // Moved values leave empty or null placeholders in the original CBOR tree,
    // so both the remaining tree and a partially assembled key are cleared
    // when any subsequent label or value validation fails.
    let mut key = CoseKey::new(coset::CoseKey::default());
    for (raw_label, raw_value) in entries {
        let label = parse_cose_key_label(raw_label)?;
        match label {
            Label::Int(value) if value == iana::KeyParameter::Kty as i64 => {
                key.inner_mut().kty = parse_key_type(raw_value)?;
            }
            Label::Int(value) if value == iana::KeyParameter::Kid as i64 => {
                key.inner_mut().key_id = parse_nonempty_bytes(raw_value)?;
            }
            Label::Int(value) if value == iana::KeyParameter::Alg as i64 => {
                key.inner_mut().alg = Some(parse_key_algorithm(raw_value)?);
            }
            Label::Int(value) if value == iana::KeyParameter::KeyOps as i64 => {
                parse_key_operations(raw_value, key.inner_mut())?;
            }
            Label::Int(value) if value == iana::KeyParameter::BaseIv as i64 => {
                key.inner_mut().base_iv = parse_nonempty_bytes(raw_value)?;
            }
            parameter_label => key
                .inner_mut()
                .params
                .push((parameter_label, take_cbor_value(raw_value))),
        }
    }

    if key.inner().kty == RegisteredLabel::Assigned(iana::KeyType::Reserved) {
        return Err(CoseError::InvalidFormat);
    }
    Ok(key)
}

fn parse_cose_key_label(value: &mut Value) -> Result<Label, CoseError> {
    match value {
        Value::Integer(integer) => i64::try_from(*integer)
            .map(Label::Int)
            .map_err(|_| CoseError::Cbor),
        Value::Text(text) => Ok(Label::Text(core::mem::take(text))),
        _ => Err(CoseError::Cbor),
    }
}

fn parse_key_type(value: &mut Value) -> Result<RegisteredLabel<iana::KeyType>, CoseError> {
    match value {
        Value::Integer(integer) => {
            RegisteredLabel::from_cbor_value(Value::Integer(*integer)).map_err(|_| CoseError::Cbor)
        }
        Value::Text(text) => Ok(RegisteredLabel::Text(core::mem::take(text))),
        _ => Err(CoseError::Cbor),
    }
}

fn parse_key_algorithm(
    value: &mut Value,
) -> Result<RegisteredLabelWithPrivate<iana::Algorithm>, CoseError> {
    match value {
        Value::Integer(integer) => {
            RegisteredLabelWithPrivate::from_cbor_value(Value::Integer(*integer))
                .map_err(|_| CoseError::Cbor)
        }
        Value::Text(text) => Ok(RegisteredLabelWithPrivate::Text(core::mem::take(text))),
        _ => Err(CoseError::Cbor),
    }
}

fn parse_key_operations(value: &mut Value, key: &mut coset::CoseKey) -> Result<(), CoseError> {
    let operations = match value {
        Value::Array(operations) if !operations.is_empty() => operations,
        _ => return Err(CoseError::Cbor),
    };
    for value in operations {
        let mut operation = match value {
            Value::Integer(integer) => RegisteredLabel::from_cbor_value(Value::Integer(*integer))
                .map_err(|_| CoseError::Cbor)?,
            Value::Text(text) => RegisteredLabel::Text(core::mem::take(text)),
            _ => return Err(CoseError::Cbor),
        };
        if key.key_ops.contains(&operation) {
            if let RegisteredLabel::Text(text) = &mut operation {
                text.zeroize();
            }
            return Err(CoseError::Cbor);
        }
        key.key_ops.insert(operation);
    }
    Ok(())
}

fn parse_nonempty_bytes(value: &mut Value) -> Result<Vec<u8>, CoseError> {
    match value {
        Value::Bytes(bytes) if !bytes.is_empty() => Ok(core::mem::take(bytes)),
        _ => Err(CoseError::Cbor),
    }
}

fn take_cbor_value(value: &mut Value) -> Value {
    core::mem::replace(value, Value::Null)
}
