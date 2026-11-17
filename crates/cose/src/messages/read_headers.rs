// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    bounded,
    read_message::{children, MAX_HEADER_BYTES},
    validate_key_map::{label, parameter},
};
use crate::{cbor_boundary, CoseError};
use reallyme_codec::cbor::general::{Frame, MajorType};

pub(super) struct Headers<'a> {
    pub protected: &'a [u8],
    pub unprotected: Frame<'a>,
    pub algorithm: Option<i64>,
    pub protected_kid: Option<&'a [u8]>,
}

pub(super) fn read<'a>(
    protected: &'a [u8],
    unprotected: &'a [u8],
) -> Result<Headers<'a>, CoseError> {
    read_with_critical(protected, unprotected, &[1, 3, 4])
}

pub(super) fn read_with_critical<'a>(
    protected: &'a [u8],
    unprotected: &'a [u8],
    understood: &[i64],
) -> Result<Headers<'a>, CoseError> {
    read_policy(protected, unprotected, understood, true)
}
pub(super) fn recipient<'a>(
    protected: &'a [u8],
    unprotected: &'a [u8],
) -> Result<Headers<'a>, CoseError> {
    read_policy(protected, unprotected, &[1, 3, 4], false)
}
fn read_policy<'a>(
    protected: &'a [u8],
    unprotected: &'a [u8],
    understood: &[i64],
    protect_algorithm: bool,
) -> Result<Headers<'a>, CoseError> {
    if protected.len() > MAX_HEADER_BYTES || unprotected.len() > MAX_HEADER_BYTES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let p = if protected.is_empty() {
        None
    } else {
        Some(bounded::validated(protected)?)
    };
    let u = bounded::validated(unprotected)?;
    let p = p
        .as_ref()
        .map(|p| children(p.frame(), MajorType::Map, 32))
        .transpose()?
        .unwrap_or_default();
    let fields = children(u.frame(), MajorType::Map, 32)?;
    let mut algorithm = None;
    let mut protected_kid = None;
    for (bucket, is_protected) in [(&p, true), (&fields, false)] {
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
                    if protect_algorithm && !is_protected {
                        return Err(CoseError::UnprotectedHeaderNotAllowed);
                    }
                    algorithm = Some(integer(value)?);
                }
                Some(2) => {
                    if !is_protected {
                        return Err(CoseError::UnsupportedCriticalHeader);
                    }
                    let critical = children(value, MajorType::Array, 32)?;
                    if critical.is_empty() {
                        return Err(CoseError::UnsupportedCriticalHeader);
                    }
                    for (index, key) in critical.iter().enumerate() {
                        // Only parameters actually interpreted here may be critical.
                        if !label(key)?.is_some_and(|label| understood.contains(&label))
                            || !p
                                .as_chunks::<2>()
                                .0
                                .iter()
                                .any(|[k, _]| k.received_bytes() == key.received_bytes())
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
                    let bytes = value.as_bytes().map_err(cbor_boundary::error)?;
                    if numeric == Some(4) && is_protected {
                        protected_kid = Some(bytes);
                    }
                }
                Some(7 | 9 | 11 | 12) if is_protected => {
                    return Err(CoseError::UnprotectedHeaderNotAllowed)
                }
                _ => {}
            }
        }
    }
    Ok(Headers {
        protected,
        unprotected: bounded::frame(unprotected)?,
        algorithm,
        protected_kid,
    })
}

pub(super) fn from_slots<'a>(
    protected: &Frame<'a>,
    unprotected: &Frame<'a>,
) -> Result<Headers<'a>, CoseError> {
    read(
        protected.as_bytes().map_err(cbor_boundary::error)?,
        unprotected.received_bytes(),
    )
}

pub(super) fn integer(frame: &Frame<'_>) -> Result<i64, CoseError> {
    i64::try_from(frame.integer().map_err(cbor_boundary::error)?.to_i128())
        .map_err(|_| CoseError::UnsupportedAlgorithm)
}

pub(super) fn optional_bytes<'a>(
    headers: &Headers<'a>,
    wanted: i64,
) -> Result<Option<&'a [u8]>, CoseError> {
    let protected = if headers.protected.is_empty() {
        None
    } else {
        Some(bounded::frame(headers.protected)?)
    };
    let p = protected
        .as_ref()
        .map(|v| children(v, MajorType::Map, 32))
        .transpose()?
        .unwrap_or_default();
    let u = children(&headers.unprotected, MajorType::Map, 32)?;
    for bucket in [&p, &u] {
        if let Some(value) = parameter(bucket, wanted)? {
            return Ok(Some(value.as_bytes().map_err(cbor_boundary::error)?));
        }
    }
    Ok(None)
}
