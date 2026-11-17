// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    bounded, read_message,
    validate_key_map::{label, parameter},
};
use crate::api::contract::{CoseCounterSignatureTarget, CoseCounterSignatureTargetKind as Kind};
use crate::{cbor_boundary, CoseError};
use reallyme_codec::cbor::general::{Frame, MajorType};

pub(super) const FULL_HEADER: i64 = 11;
pub(super) const ABBREVIATED_HEADER: i64 = 12;
pub(super) const COUNTER_TAG: u64 = 19;
const MAX_AUTHENTICATOR_BYTES: usize = 16_384;

pub(super) struct Target<'a> {
    pub fields: Vec<Frame<'a>>,
    pub tag: Option<u64>,
    pub protected: &'a [u8],
    pub payload: &'a [u8],
    pub other: Option<&'a [u8]>,
}

// This validates the target's format and byte boundaries, not its algorithm,
// primary authentication or trust policy. Unknown primary critical semantics
// remain the responsibility of that independent verification operation.
pub(super) fn headers(protected: &[u8], unprotected: &Frame<'_>) -> Result<(), CoseError> {
    if protected.len() > read_message::MAX_HEADER_BYTES
        || unprotected.received_bytes().len() > read_message::MAX_HEADER_BYTES
    {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let p = if protected.is_empty() {
        None
    } else {
        Some(bounded::validated(protected)?)
    };
    let p = p
        .as_ref()
        .map(|v| {
            read_message::children(
                v.frame(),
                MajorType::Map,
                read_message::MAX_HEADER_PARAMETERS,
            )
        })
        .transpose()?
        .unwrap_or_default();
    let u = read_message::children(
        unprotected,
        MajorType::Map,
        read_message::MAX_HEADER_PARAMETERS,
    )?;
    for (bucket, is_protected) in [(&p, true), (&u, false)] {
        for [key, value] in bucket.as_chunks::<2>().0 {
            let numeric = label(key)?;
            if !is_protected
                && p.as_chunks::<2>()
                    .0
                    .iter()
                    .any(|[prior, _]| prior.received_bytes() == key.received_bytes())
            {
                return Err(CoseError::DuplicateMapLabel);
            }
            match numeric {
                Some(1) => {
                    label(value)?;
                }
                Some(2) => {
                    if !is_protected {
                        return Err(CoseError::UnsupportedCriticalHeader);
                    }
                    let critical = read_message::children(
                        value,
                        MajorType::Array,
                        read_message::MAX_HEADER_PARAMETERS,
                    )?;
                    if critical.is_empty() {
                        return Err(CoseError::UnsupportedCriticalHeader);
                    }
                    for (index, key) in critical.iter().enumerate() {
                        if label(key)? == Some(2) {
                            return Err(CoseError::UnsupportedCriticalHeader);
                        }
                        if !p
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .any(|[prior, _]| prior.received_bytes() == key.received_bytes())
                            || critical
                                .get(..index)
                                .ok_or(CoseError::InvalidFormat)?
                                .iter()
                                .any(|prior| prior.received_bytes() == key.received_bytes())
                        {
                            return Err(CoseError::UnsupportedCriticalHeader);
                        }
                    }
                }
                Some(3) => match value.header().major_type() {
                    MajorType::Unsigned => {}
                    MajorType::Text
                        if crate::limits::valid_media_type(
                            value.as_text().map_err(cbor_boundary::error)?,
                        ) => {}
                    _ => return Err(CoseError::InvalidFormat),
                },
                Some(4..=6) => {
                    value.as_bytes().map_err(cbor_boundary::error)?;
                }
                Some(7 | 9) => return Err(CoseError::UnsupportedCriticalHeader),
                Some(FULL_HEADER | ABBREVIATED_HEADER) if is_protected => {
                    return Err(CoseError::UnprotectedHeaderNotAllowed)
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn signature(frame: &Frame<'_>) -> Result<(), CoseError> {
    let fields = read_message::children(frame, MajorType::Array, 3)?;
    let [protected, unprotected, signature] = fields.as_slice() else {
        return Err(CoseError::InvalidFormat);
    };
    headers(
        protected.as_bytes().map_err(cbor_boundary::error)?,
        unprotected,
    )?;
    authenticator(signature)?;
    Ok(())
}
fn authenticator<'a>(frame: &Frame<'a>) -> Result<&'a [u8], CoseError> {
    let bytes = frame.as_bytes().map_err(cbor_boundary::error)?;
    if bytes.is_empty() || bytes.len() > MAX_AUTHENTICATOR_BYTES {
        return Err(CoseError::InvalidSignatureEncoding);
    }
    Ok(bytes)
}

pub(super) fn parse(request: &CoseCounterSignatureTarget) -> Result<Target<'_>, CoseError> {
    let kind = request.kind.as_known().ok_or(CoseError::InvalidFormat)?;
    let expected_tag = match kind {
        Kind::Sign => Some(read_message::COSE_SIGN_TAG),
        Kind::Sign1 => Some(read_message::COSE_SIGN1_TAG),
        Kind::Encrypt => Some(read_message::COSE_ENCRYPT_TAG),
        Kind::Encrypt0 => Some(read_message::COSE_ENCRYPT0_TAG),
        Kind::Mac => Some(read_message::COSE_MAC_TAG),
        Kind::Mac0 => Some(read_message::COSE_MAC0_TAG),
        Kind::Countersignature => Some(COUNTER_TAG),
        Kind::Signature | Kind::Recipient => None,
        _ => return Err(CoseError::InvalidFormat),
    };
    let item = bounded::validated(&request.encoded)?;
    let tagged = item.frame().header().major_type() == MajorType::Tag;
    if tagged && expected_tag.is_none() {
        return Err(CoseError::UnexpectedCborTag);
    }
    let root = if tagged {
        item.frame()
            .children()
            .map_err(cbor_boundary::error)?
            .next()
            .ok_or(CoseError::Cbor)?
            .map_err(cbor_boundary::error)?
    } else {
        bounded::frame(&request.encoded)?
    };
    let count = usize::try_from(root.header().argument().ok_or(CoseError::InvalidFormat)?)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    let valid_count = match kind {
        Kind::Sign | Kind::Sign1 | Kind::Mac0 | Kind::Encrypt => count == 4,
        Kind::Mac => count == 5,
        Kind::Encrypt0 | Kind::Signature | Kind::Countersignature => count == 3,
        Kind::Recipient => matches!(count, 3 | 4),
        _ => false,
    };
    if !valid_count {
        return Err(CoseError::InvalidFormat);
    }
    let fields = read_message::envelope(
        &request.encoded,
        expected_tag.unwrap_or_default(),
        request.envelope,
        count,
    )?;
    let protected = fields
        .first()
        .ok_or(CoseError::InvalidFormat)?
        .as_bytes()
        .map_err(cbor_boundary::error)?;
    headers(protected, fields.get(1).ok_or(CoseError::InvalidFormat)?)?;
    let content = fields.get(2).ok_or(CoseError::InvalidFormat)?;
    if matches!(
        kind,
        Kind::Signature | Kind::Countersignature | Kind::Recipient
    ) && request.detached_content.is_some()
    {
        return Err(CoseError::InvalidFormat);
    }
    let payload = read_message::payload(content, request.detached_content.as_deref())?;
    let other = if matches!(kind, Kind::Sign1 | Kind::Mac | Kind::Mac0) {
        Some(authenticator(
            fields.get(3).ok_or(CoseError::InvalidFormat)?,
        )?)
    } else {
        None
    };
    match kind {
        Kind::Sign => {
            let signatures = read_message::children(
                fields.get(3).ok_or(CoseError::InvalidFormat)?,
                MajorType::Array,
                read_message::MAX_SIGNATURES,
            )?;
            if signatures.is_empty() {
                return Err(CoseError::InvalidFormat);
            }
            for value in &signatures {
                signature(value)?;
            }
        }
        Kind::Encrypt | Kind::Mac => super::recipient::validate_tree(
            fields.last().ok_or(CoseError::InvalidFormat)?,
            1,
            &mut 0,
        )?,
        Kind::Signature | Kind::Countersignature => {
            authenticator(content)?;
        }
        Kind::Recipient => {
            if let Some(recipients) = fields.get(3) {
                super::recipient::validate_tree(recipients, 2, &mut 1)?;
            }
        }
        _ => {}
    }
    Ok(Target {
        fields,
        tag: if tagged { expected_tag } else { None },
        protected,
        payload,
        other,
    })
}

pub(super) fn header<'a>(target: &Target<'a>, wanted: i64) -> Result<Option<Frame<'a>>, CoseError> {
    let fields = read_message::children(
        target.fields.get(1).ok_or(CoseError::InvalidFormat)?,
        MajorType::Map,
        32,
    )?;
    if let Some(value) = parameter(&fields, wanted)? {
        return Ok(Some(bounded::frame(value.received_bytes())?));
    }
    Ok(None)
}
