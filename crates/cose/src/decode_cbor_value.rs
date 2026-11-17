// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ownership adapter from codec receipts to the existing internal COSE model.

use ciborium::value::Value;
use reallyme_codec::cbor::general::{Frame, MajorType};
use zeroize::Zeroizing;

use crate::{cbor_boundary, zeroize_coset::SensitiveCborValue, CoseError};

pub(crate) fn decode(frame: &Frame<'_>) -> Result<SensitiveCborValue, CoseError> {
    let value = match frame.header().major_type() {
        MajorType::Unsigned | MajorType::Negative => Value::Integer(
            frame
                .integer()
                .map_err(cbor_boundary::error)?
                .to_i128()
                .try_into()
                .map_err(|_| CoseError::Cbor)?,
        ),
        MajorType::Bytes => {
            let bytes = frame.as_bytes().map_err(cbor_boundary::error)?;
            let mut owned = Zeroizing::new(Vec::new());
            owned
                .try_reserve_exact(bytes.len())
                .map_err(|_| CoseError::ResourceLimitExceeded)?;
            owned.extend_from_slice(bytes);
            Value::Bytes(core::mem::take(&mut *owned))
        }
        MajorType::Text => {
            let text = frame.as_text().map_err(cbor_boundary::error)?;
            let mut owned = Zeroizing::new(String::new());
            owned
                .try_reserve_exact(text.len())
                .map_err(|_| CoseError::ResourceLimitExceeded)?;
            owned.push_str(text);
            Value::Text(core::mem::take(&mut *owned))
        }
        MajorType::Array => return array(frame),
        MajorType::Map => return map(frame),
        MajorType::Tag => {
            let mut children = frame.children().map_err(cbor_boundary::error)?;
            let child = children
                .next()
                .ok_or(CoseError::Cbor)?
                .map_err(cbor_boundary::error)?;
            let mut owner = decode(&child)?;
            Value::Tag(
                frame.header().argument().ok_or(CoseError::Cbor)?,
                Box::new(owner.take_value()),
            )
        }
        MajorType::Simple => match frame.simple_value().map_err(cbor_boundary::error)? {
            20 => Value::Bool(false),
            21 => Value::Bool(true),
            22 => Value::Null,
            // The compatibility tree cannot represent undefined or arbitrary
            // simple values. Admission rejects them before copying any input.
            _ => return Err(CoseError::Cbor),
        },
        _ => return Err(CoseError::Cbor),
    };
    Ok(SensitiveCborValue::from_value(value))
}

fn count(frame: &Frame<'_>) -> Result<usize, CoseError> {
    usize::try_from(frame.header().argument().ok_or(CoseError::Cbor)?)
        .map_err(|_| CoseError::ResourceLimitExceeded)
}

fn array(frame: &Frame<'_>) -> Result<SensitiveCborValue, CoseError> {
    let mut owner = SensitiveCborValue::from_value(Value::Array(Vec::new()));
    let Value::Array(values) = owner.value_mut() else {
        return Err(CoseError::Cbor);
    };
    values
        .try_reserve_exact(count(frame)?)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for child in frame.children().map_err(cbor_boundary::error)? {
        let mut child = decode(&child.map_err(cbor_boundary::error)?)?;
        values.push(child.take_value());
    }
    Ok(owner)
}

fn map(frame: &Frame<'_>) -> Result<SensitiveCborValue, CoseError> {
    let mut owner = SensitiveCborValue::from_value(Value::Map(Vec::new()));
    let Value::Map(entries) = owner.value_mut() else {
        return Err(CoseError::Cbor);
    };
    entries
        .try_reserve_exact(count(frame)?)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    let mut children = frame.children().map_err(cbor_boundary::error)?;
    while let Some(key) = children.next() {
        let mut key = decode(&key.map_err(cbor_boundary::error)?)?;
        let value = children
            .next()
            .ok_or(CoseError::Cbor)?
            .map_err(cbor_boundary::error)?;
        let mut value = decode(&value)?;
        // Both owners remain guarded while either recursive decode can fail.
        // The vector has already reserved all slots before owners are moved.
        entries.push((key.take_value(), value.take_value()));
    }
    Ok(owner)
}
