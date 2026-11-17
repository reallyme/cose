// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::bounded;
use crate::api::contract::{CoseContentMode, CoseEnvelopePolicy};
use crate::{cbor_boundary, CoseError};
use reallyme_codec::cbor::general::{Frame, MajorType, ValueRef};

pub(super) const COSE_SIGN_TAG: u64 = 98;
pub(super) const COSE_SIGN1_TAG: u64 = 18;
pub(super) const COSE_ENCRYPT_TAG: u64 = 96;
pub(super) const COSE_ENCRYPT0_TAG: u64 = 16;
pub(super) const COSE_MAC_TAG: u64 = 97;
pub(super) const COSE_MAC0_TAG: u64 = 17;
pub(super) const MAX_HEADER_PARAMETERS: usize = 32;
pub(super) const MAX_SIGNATURES: usize = 32;
pub(super) const MAX_HEADER_BYTES: usize = 16_384;
pub(super) const MAX_AAD_BYTES: usize = 65_536;

pub(super) fn children<'a>(
    frame: &Frame<'a>,
    major: MajorType,
    max: usize,
) -> Result<Vec<Frame<'a>>, CoseError> {
    if frame.header().major_type() != major {
        return Err(CoseError::InvalidFormat);
    }
    let count = usize::try_from(frame.header().argument().ok_or(CoseError::Cbor)?)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    if count > max {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let slots = if major == MajorType::Map {
        count
            .checked_mul(2)
            .ok_or(CoseError::ResourceLimitExceeded)?
    } else {
        count
    };
    let mut output = Vec::new();
    output
        .try_reserve_exact(slots)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for child in frame.children().map_err(cbor_boundary::error)? {
        output.push(child.map_err(cbor_boundary::error)?);
    }
    Ok(output)
}

pub(super) fn envelope<'a>(
    encoded: &'a [u8],
    tag: u64,
    policy: buffa::EnumValue<CoseEnvelopePolicy>,
    count: usize,
) -> Result<Vec<Frame<'a>>, CoseError> {
    let item = bounded::validated(encoded)?;
    let root = item.frame();
    let tagged = root.header().major_type() == MajorType::Tag;
    match policy.as_known() {
        Some(CoseEnvelopePolicy::Tagged) if tagged => {}
        Some(CoseEnvelopePolicy::Untagged) if !tagged => {}
        Some(CoseEnvelopePolicy::Either) => {}
        _ => return Err(CoseError::UnexpectedCborTag),
    }
    let body = if tagged {
        if root.header().argument() != Some(tag) {
            return Err(CoseError::UnexpectedCborTag);
        }
        root.children()
            .map_err(cbor_boundary::error)?
            .next()
            .ok_or(CoseError::Cbor)?
            .map_err(cbor_boundary::error)?
    } else {
        bounded::frame(encoded)?
    };
    let values = children(&body, MajorType::Array, count)?;
    if values.len() != count {
        return Err(CoseError::InvalidFormat);
    }
    Ok(values)
}

pub(super) fn payload<'a>(
    slot: &Frame<'a>,
    detached: Option<&'a [u8]>,
) -> Result<&'a [u8], CoseError> {
    let value = match detached {
        Some(value)
            if slot.header().major_type() == MajorType::Simple
                && slot.simple_value().map_err(cbor_boundary::error)? == 22 =>
        {
            value
        }
        None if slot.header().major_type() == MajorType::Bytes => {
            slot.as_bytes().map_err(cbor_boundary::error)?
        }
        _ => return Err(CoseError::InvalidFormat),
    };
    if value.len() > bounded::MAX_MESSAGE_BYTES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    Ok(value)
}

pub(super) fn content(
    payload: &[u8],
    mode: buffa::EnumValue<CoseContentMode>,
) -> Result<ValueRef<'_>, CoseError> {
    if payload.len() > bounded::MAX_MESSAGE_BYTES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    match mode.as_known() {
        Some(CoseContentMode::Attached) => Ok(ValueRef::Bytes(payload)),
        Some(CoseContentMode::Detached) => Ok(ValueRef::Null),
        _ => Err(CoseError::InvalidFormat),
    }
}
pub(super) fn aad(bytes: &[u8]) -> Result<(), CoseError> {
    if bytes.len() > MAX_AAD_BYTES {
        Err(CoseError::ResourceLimitExceeded)
    } else {
        Ok(())
    }
}
