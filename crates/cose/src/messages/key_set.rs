// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::cbor::general::{Frame, MajorType, MapEntry, ValueRef};
use reallyme_cose_proto::{
    generated::proto::reallyme::cose::v1::{
        self as contract, __buffa::oneof::cose_key_set_entry::Outcome, CoseKeySetKeyType as Kind,
        CoseKeySetProjection as Projection,
    },
    SecretBytes,
};

use super::{
    bounded,
    validate_key_map::{entries, label, parameter, validate},
};
use crate::{cbor_boundary, CoseError};

fn policy(
    value: Option<&contract::CoseKeySetPolicy>,
) -> Result<&contract::CoseKeySetPolicy, CoseError> {
    let value = value.ok_or(CoseError::InvalidFormat)?;
    if !matches!(
        value.projection.as_known(),
        Some(Projection::SensitiveStorage | Projection::PublicParameters)
    ) {
        return Err(CoseError::InvalidFormat);
    }
    if value.allowed_key_types.is_empty() || value.allowed_key_types.len() > 5 {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    for (index, kind) in value.allowed_key_types.iter().enumerate() {
        if !matches!(
            kind.as_known(),
            Some(Kind::Okp | Kind::Ec2 | Kind::Rsa | Kind::Symmetric | Kind::Akp)
        ) {
            return Err(CoseError::UnsupportedAlgorithm);
        }
        if value
            .allowed_key_types
            .get(..index)
            .ok_or(CoseError::ResourceLimitExceeded)?
            .contains(kind)
        {
            return Err(CoseError::InvalidFormat);
        }
    }
    Ok(value)
}

fn member(
    encoded: &[u8],
    policy: &contract::CoseKeySetPolicy,
) -> Result<contract::CoseKeySetMember, CoseError> {
    if encoded.len() > crate::limits::MAX_COSE_KEY_BYTES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let frame = bounded::validated(encoded)?;
    let fields = entries(frame.frame())?;
    let kind = validate(&fields)?;
    if !policy
        .allowed_key_types
        .iter()
        .any(|allowed| *allowed == kind)
    {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    let encoded = if policy.projection == Projection::SensitiveStorage {
        bounded::copy(encoded)?
    } else {
        project(&fields, kind)?
    };
    Ok(contract::CoseKeySetMember {
        key_type: kind.into(),
        encoded,
    })
}

fn project(fields: &[Frame<'_>], kind: Kind) -> Result<SecretBytes, CoseError> {
    let labels: &[i64] = match kind {
        Kind::Okp | Kind::Rsa => &[1, 3, -1, -2],
        Kind::Ec2 => &[1, 3, -1, -2, -3],
        Kind::Akp => &[1, 3, -1],
        _ => return Err(CoseError::InvalidKeyMaterial),
    };
    for required in labels.iter().filter(|label| **label != 3) {
        parameter(fields, *required)?.ok_or(CoseError::MissingKeyMaterial)?;
    }
    let mut projected = Vec::new();
    projected
        .try_reserve_exact(labels.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for wanted in labels {
        for pair in fields.as_chunks::<2>().0 {
            let key = pair.first().ok_or(CoseError::Cbor)?;
            if label(key)? == Some(*wanted) {
                projected.push(MapEntry::new(
                    ValueRef::Received(key),
                    ValueRef::Received(pair.get(1).ok_or(CoseError::Cbor)?),
                ));
            }
        }
    }
    let value = ValueRef::Map(&projected);
    bounded::encode(&value)
}

pub(crate) fn parse(
    request: &contract::CoseKeySetParseRequest,
) -> Result<contract::CoseKeySetParseResult, CoseError> {
    let policy = policy(request.policy.as_option())?;
    // Frame the outer array first, then validate each key independently. A
    // semantically invalid member must not discard its valid neighbours.
    let set = bounded::frame(&request.encoded)?;
    if set.header().major_type() != MajorType::Array {
        return Err(CoseError::InvalidFormat);
    }
    let count = usize::try_from(set.header().argument().ok_or(CoseError::Cbor)?)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    if count == 0 {
        return Err(CoseError::InvalidFormat);
    }
    if count > bounded::MAX_KEY_SET_MEMBERS {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for (index, key) in set.children().map_err(cbor_boundary::error)?.enumerate() {
        let key = key.map_err(cbor_boundary::error)?;
        let outcome = match member(key.received_bytes(), policy) {
            Ok(key) => Outcome::Key(Box::new(key)),
            Err(error) => Outcome::Rejected(error.reason().into()),
        };
        entries.push(contract::CoseKeySetEntry {
            source_index: u32::try_from(index).map_err(|_| CoseError::ResourceLimitExceeded)?,
            outcome: Some(outcome),
        });
    }
    Ok(contract::CoseKeySetParseResult {
        entries: entries.into(),
    })
}

pub(crate) fn create(
    request: &contract::CoseKeySetCreateRequest,
) -> Result<contract::CoseKeySetCreateResult, CoseError> {
    let policy = policy(request.policy.as_option())?;
    if request.keys.is_empty() {
        return Err(CoseError::InvalidFormat);
    }
    if request.keys.len() > bounded::MAX_KEY_SET_MEMBERS {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let mut keys = Vec::new();
    keys.try_reserve_exact(request.keys.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for encoded in &request.keys {
        let mut key = member(encoded, policy)?;
        keys.push(core::mem::take(&mut key.encoded));
    }
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(keys.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for key in &keys {
        frames.push(bounded::frame(key)?);
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(frames.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for frame in &frames {
        values.push(ValueRef::Received(frame));
    }
    let value = ValueRef::Array(&values);
    let encoded = bounded::encode(&value)?;
    Ok(contract::CoseKeySetCreateResult {
        encoded,
        key_count: u32::try_from(keys.len()).map_err(|_| CoseError::ResourceLimitExceeded)?,
    })
}

pub(crate) fn valid_parsed_result(result: &contract::CoseKeySetParseResult) -> bool {
    if result.entries.is_empty() || result.entries.len() > bounded::MAX_KEY_SET_MEMBERS {
        return false;
    }
    result.entries.iter().enumerate().all(|(index, entry)| {
        if usize::try_from(entry.source_index).ok() != Some(index) {
            return false;
        }
        match entry.outcome.as_ref() {
            Some(Outcome::Key(key)) => {
                if key.encoded.len() > crate::limits::MAX_COSE_KEY_BYTES {
                    return false;
                }
                bounded::validated(&key.encoded)
                    .and_then(|frame| entries(frame.frame()))
                    .and_then(|fields| validate(&fields))
                    .is_ok_and(|kind| key.key_type == kind)
            }
            Some(Outcome::Rejected(reason)) => reason
                .as_known()
                .is_some_and(|reason| reason != contract::CoseErrorReason::Unspecified),
            None => false,
        }
    })
}

pub(crate) fn valid_created_result(result: &contract::CoseKeySetCreateResult) -> bool {
    result.key_count != 0
        && usize::try_from(result.key_count).is_ok_and(|n| n <= bounded::MAX_KEY_SET_MEMBERS)
        && bounded::validated(&result.encoded).is_ok_and(|item| {
            item.frame().header().major_type() == MajorType::Array
                && item.frame().header().argument() == Some(u64::from(result.key_count))
        })
}
