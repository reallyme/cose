// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::cbor::general::{Frame, MajorType};
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseKeySetKeyType;

use crate::{cbor_boundary, CoseError};

const MAX_KEY_PARAMETERS: usize = 32;
const MAX_KEY_OPERATIONS: u64 = 16;

pub(super) fn label(frame: &Frame<'_>) -> Result<Option<i64>, CoseError> {
    match frame.header().major_type() {
        MajorType::Unsigned | MajorType::Negative => {
            Ok(i64::try_from(frame.integer().map_err(cbor_boundary::error)?.to_i128()).ok())
        }
        MajorType::Text => Ok(None),
        _ => Err(CoseError::InvalidFormat),
    }
}

pub(super) fn entries<'a>(frame: &Frame<'a>) -> Result<Vec<Frame<'a>>, CoseError> {
    if frame.header().major_type() != MajorType::Map {
        return Err(CoseError::InvalidFormat);
    }
    let count = usize::try_from(frame.header().argument().ok_or(CoseError::Cbor)?)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    if count > MAX_KEY_PARAMETERS {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let mut fields = Vec::new();
    fields
        .try_reserve_exact(
            count
                .checked_mul(2)
                .ok_or(CoseError::ResourceLimitExceeded)?,
        )
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for child in frame.children().map_err(cbor_boundary::error)? {
        fields.push(child.map_err(cbor_boundary::error)?);
    }
    Ok(fields)
}

pub(super) fn parameter<'a, 'b>(
    fields: &'b [Frame<'a>],
    expected: i64,
) -> Result<Option<&'b Frame<'a>>, CoseError> {
    for entry in fields.as_chunks::<2>().0 {
        let key = entry.first().ok_or(CoseError::Cbor)?;
        if label(key)? == Some(expected) {
            return Ok(entry.get(1));
        }
    }
    Ok(None)
}

pub(super) fn validate(fields: &[Frame<'_>]) -> Result<CoseKeySetKeyType, CoseError> {
    let kty = parameter(fields, 1)?.ok_or(CoseError::InvalidFormat)?;
    let kty = match label(kty)? {
        Some(1) => CoseKeySetKeyType::Okp,
        Some(2) => CoseKeySetKeyType::Ec2,
        Some(3) => CoseKeySetKeyType::Rsa,
        Some(4) => CoseKeySetKeyType::Symmetric,
        Some(7) => CoseKeySetKeyType::Akp,
        _ => return Err(CoseError::UnsupportedAlgorithm),
    };
    for entry in fields.as_chunks::<2>().0 {
        let key = entry.first().ok_or(CoseError::Cbor)?;
        let value = entry.get(1).ok_or(CoseError::Cbor)?;
        match label(key)? {
            Some(2 | 5) => {
                value.as_bytes().map_err(cbor_boundary::error)?;
            }
            Some(3) => {
                label(value)?;
            }
            Some(4) => validate_operations(value)?,
            _ => {}
        }
    }
    let public = |key| {
        parameter(fields, key)?
            .map(|value| value.as_bytes().map_err(cbor_boundary::error))
            .transpose()
    };
    match kty {
        CoseKeySetKeyType::Okp => {
            label(parameter(fields, -1)?.ok_or(CoseError::InvalidKeyMaterial)?)?;
            if public(-2)?.is_none() && public(-4)?.is_none() {
                return Err(CoseError::MissingKeyMaterial);
            }
        }
        CoseKeySetKeyType::Ec2 => {
            label(parameter(fields, -1)?.ok_or(CoseError::InvalidKeyMaterial)?)?;
            let x = public(-2)?;
            let d = public(-4)?;
            let y = parameter(fields, -3)?;
            if let Some(y) = y {
                if y.header().major_type() == MajorType::Simple {
                    if !matches!(y.simple_value().map_err(cbor_boundary::error)?, 20 | 21) {
                        return Err(CoseError::InvalidFormat);
                    }
                } else {
                    y.as_bytes().map_err(cbor_boundary::error)?;
                }
            }
            if d.is_none() && (x.is_none() || y.is_none()) {
                return Err(CoseError::MissingKeyMaterial);
            }
        }
        CoseKeySetKeyType::Rsa => {
            if public(-1)?.is_none_or(|v| v.is_empty()) || public(-2)?.is_none_or(|v| v.is_empty())
            {
                return Err(CoseError::MissingKeyMaterial);
            }
            for label in [-3, -4, -5, -6, -7, -8] {
                public(label)?;
            }
        }
        CoseKeySetKeyType::Symmetric | CoseKeySetKeyType::Akp => {
            if public(-1)?.is_none_or(|v| v.is_empty()) {
                return Err(CoseError::MissingKeyMaterial);
            }
            if kty == CoseKeySetKeyType::Akp {
                public(-2)?;
            }
        }
        _ => return Err(CoseError::UnsupportedAlgorithm),
    }
    Ok(kty)
}

fn validate_operations(value: &Frame<'_>) -> Result<(), CoseError> {
    if value.header().major_type() != MajorType::Array {
        return Err(CoseError::InvalidFormat);
    }
    let count = value.header().argument().ok_or(CoseError::Cbor)?;
    if count == 0 || count > MAX_KEY_OPERATIONS {
        return Err(CoseError::InvalidKeyMaterial);
    }
    let mut seen = Vec::new();
    seen.try_reserve_exact(usize::try_from(count).map_err(|_| CoseError::ResourceLimitExceeded)?)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for operation in value.children().map_err(cbor_boundary::error)? {
        let operation = operation.map_err(cbor_boundary::error)?;
        label(&operation)?;
        if seen.contains(&operation.received_bytes()) {
            return Err(CoseError::InvalidKeyMaterial);
        }
        seen.push(operation.received_bytes());
    }
    Ok(())
}
