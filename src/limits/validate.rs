// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Resource limits and deterministic CBOR boundary checks.

use std::io::Cursor;

use ciborium::{de::from_reader, value::Value};

use crate::CoseError;

/// Maximum accepted encoded COSE_Sign1 size.
///
/// The limit is intentionally small for identity credentials: callers that need
/// large payloads should use detached signing and bind the payload through an
/// application-level transport with its own resource policy.
pub const MAX_COSE_SIGN1_BYTES: usize = 65_536;

/// Maximum accepted encoded COSE_Key size.
///
/// Supported OKP and EC2 key shapes are compact. A larger object is treated as
/// hostile or outside this crate's supported public API surface.
pub const MAX_COSE_KEY_BYTES: usize = 16_384;

/// Maximum accepted detached payload size for signing and verification.
pub const MAX_DETACHED_PAYLOAD_BYTES: usize = 1_048_576;

const CBOR_INDEFINITE_ADDITIONAL_INFO: u8 = 0x1f;
const CBOR_ADDITIONAL_INFO_MASK: u8 = 0x1f;
const CBOR_MAJOR_TYPE_SHIFT: u8 = 5;
const CBOR_UINT_MAJOR: u8 = 0;
const CBOR_NEGATIVE_INT_MAJOR: u8 = 1;
const CBOR_BYTES_MAJOR: u8 = 2;
const CBOR_TEXT_MAJOR: u8 = 3;
const CBOR_ARRAY_MAJOR: u8 = 4;
const CBOR_MAP_MAJOR: u8 = 5;
const CBOR_TAG_MAJOR: u8 = 6;
const CBOR_SIMPLE_MAJOR: u8 = 7;
const CBOR_ONE_BYTE_LENGTH: u8 = 24;
const CBOR_TWO_BYTE_LENGTH: u8 = 25;
const CBOR_FOUR_BYTE_LENGTH: u8 = 26;
const CBOR_EIGHT_BYTE_LENGTH: u8 = 27;
const COSE_SIGN1_TAG: u64 = 18;
const MAX_CBOR_DEPTH: usize = 32;

#[derive(Clone, Copy)]
pub(crate) enum CborTagPolicy {
    #[cfg(feature = "cose-crypto")]
    AllowCoseSign1Root,
    RejectAllTags,
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn validate_cose_sign1_bytes_with_limit(
    bytes: &[u8],
    max_len: usize,
) -> Result<(), CoseError> {
    validate_cbor_bytes(bytes, max_len, CborTagPolicy::AllowCoseSign1Root)?;
    validate_cose_sign1_protected_header(bytes)
}

pub(crate) fn validate_cose_key_bytes(bytes: &[u8]) -> Result<(), CoseError> {
    validate_cbor_bytes(bytes, MAX_COSE_KEY_BYTES, CborTagPolicy::RejectAllTags)
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn validate_detached_payload(payload: &[u8]) -> Result<(), CoseError> {
    validate_detached_payload_with_limit(payload, MAX_DETACHED_PAYLOAD_BYTES)
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn validate_detached_payload_with_limit(
    payload: &[u8],
    max_len: usize,
) -> Result<(), CoseError> {
    if payload.len() > max_len {
        return Err(CoseError::ResourceLimitExceeded);
    }

    Ok(())
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn validate_protected_header_bytes(bytes: &[u8]) -> Result<(), CoseError> {
    if bytes.is_empty() {
        return Ok(());
    }

    reject_indefinite_cbor(bytes)?;

    let value: Value = from_reader(Cursor::new(bytes)).map_err(|_| CoseError::Cbor)?;
    if !matches!(value, Value::Map(_)) {
        return Err(CoseError::InvalidFormat);
    }

    validate_tags(&value, CborTagPolicy::RejectAllTags, 0, true)
}

fn validate_cbor_bytes(
    bytes: &[u8],
    max_len: usize,
    tag_policy: CborTagPolicy,
) -> Result<(), CoseError> {
    if bytes.is_empty() {
        return Err(CoseError::Cbor);
    }

    if bytes.len() > max_len {
        return Err(CoseError::ResourceLimitExceeded);
    }

    reject_indefinite_cbor(bytes)?;

    let value: Value = from_reader(Cursor::new(bytes)).map_err(|_| CoseError::Cbor)?;
    validate_tags(&value, tag_policy, 0, true)
}

#[cfg(feature = "cose-crypto")]
fn validate_cose_sign1_protected_header(bytes: &[u8]) -> Result<(), CoseError> {
    let value: Value = from_reader(Cursor::new(bytes)).map_err(|_| CoseError::Cbor)?;
    let sign1 = match &value {
        Value::Tag(tag, inner) if *tag == COSE_SIGN1_TAG => inner.as_ref(),
        other => other,
    };

    let Value::Array(items) = sign1 else {
        return Ok(());
    };

    let Some(Value::Bytes(protected)) = items.first() else {
        return Ok(());
    };

    validate_protected_header_bytes(protected)
}

fn reject_indefinite_cbor(bytes: &[u8]) -> Result<(), CoseError> {
    let parsed_len = parse_cbor_item(bytes, 0, 0)?;
    if parsed_len == bytes.len() {
        Ok(())
    } else {
        Err(CoseError::Cbor)
    }
}

fn parse_cbor_item(bytes: &[u8], offset: usize, depth: usize) -> Result<usize, CoseError> {
    if depth > MAX_CBOR_DEPTH {
        return Err(CoseError::ResourceLimitExceeded);
    }

    let first = *bytes.get(offset).ok_or(CoseError::Cbor)?;
    let major = first >> CBOR_MAJOR_TYPE_SHIFT;
    let additional = first & CBOR_ADDITIONAL_INFO_MASK;
    let value_start = offset
        .checked_add(1)
        .ok_or(CoseError::ResourceLimitExceeded)?;

    if additional == CBOR_INDEFINITE_ADDITIONAL_INFO {
        return match major {
            CBOR_BYTES_MAJOR | CBOR_TEXT_MAJOR | CBOR_ARRAY_MAJOR | CBOR_MAP_MAJOR => {
                Err(CoseError::NonCanonicalCbor)
            }
            _ => Err(CoseError::Cbor),
        };
    }

    match major {
        CBOR_UINT_MAJOR | CBOR_NEGATIVE_INT_MAJOR => {
            read_argument(bytes, value_start, additional).map(|(_, next_offset)| next_offset)
        }
        CBOR_BYTES_MAJOR | CBOR_TEXT_MAJOR => {
            let (len, data_offset) = read_argument(bytes, value_start, additional)?;
            data_offset
                .checked_add(len)
                .filter(|end| *end <= bytes.len())
                .ok_or(CoseError::Cbor)
        }
        CBOR_ARRAY_MAJOR => {
            let (len, mut next_offset) = read_argument(bytes, value_start, additional)?;
            for _ in 0..len {
                next_offset = parse_cbor_item(bytes, next_offset, next_depth(depth)?)?;
            }
            Ok(next_offset)
        }
        CBOR_MAP_MAJOR => {
            let (len, mut next_offset) = read_argument(bytes, value_start, additional)?;
            let mut key_ranges = Vec::new();
            for _ in 0..len {
                let child_depth = next_depth(depth)?;
                let key_start = next_offset;
                let key_end = parse_cbor_item(bytes, next_offset, child_depth)?;
                reject_duplicate_raw_key(bytes, &key_ranges, key_start, key_end)?;
                key_ranges.push((key_start, key_end));
                next_offset = key_end;
                next_offset = parse_cbor_item(bytes, next_offset, child_depth)?;
            }
            Ok(next_offset)
        }
        CBOR_TAG_MAJOR => {
            let (_, next_offset) = read_argument(bytes, value_start, additional)?;
            parse_cbor_item(bytes, next_offset, next_depth(depth)?)
        }
        CBOR_SIMPLE_MAJOR => parse_simple(bytes, value_start, additional),
        _ => Err(CoseError::Cbor),
    }
}

fn read_argument(bytes: &[u8], offset: usize, additional: u8) -> Result<(usize, usize), CoseError> {
    match additional {
        value if value < CBOR_ONE_BYTE_LENGTH => Ok((usize::from(value), offset)),
        CBOR_ONE_BYTE_LENGTH => {
            let value = *bytes.get(offset).ok_or(CoseError::Cbor)?;
            if value < CBOR_ONE_BYTE_LENGTH {
                return Err(CoseError::NonCanonicalCbor);
            }
            Ok((
                usize::from(value),
                offset
                    .checked_add(1)
                    .ok_or(CoseError::ResourceLimitExceeded)?,
            ))
        }
        CBOR_TWO_BYTE_LENGTH => {
            let end = offset
                .checked_add(2)
                .ok_or(CoseError::ResourceLimitExceeded)?;
            let data = bytes.get(offset..end).ok_or(CoseError::Cbor)?;
            let value = u16::from_be_bytes([data[0], data[1]]);
            if value <= u16::from(u8::MAX) {
                return Err(CoseError::NonCanonicalCbor);
            }
            Ok((usize::from(value), end))
        }
        CBOR_FOUR_BYTE_LENGTH => {
            let end = offset
                .checked_add(4)
                .ok_or(CoseError::ResourceLimitExceeded)?;
            let data = bytes.get(offset..end).ok_or(CoseError::Cbor)?;
            let value = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            if value <= u32::from(u16::MAX) {
                return Err(CoseError::NonCanonicalCbor);
            }
            let len = usize::try_from(value).map_err(|_| CoseError::ResourceLimitExceeded)?;
            Ok((len, end))
        }
        CBOR_EIGHT_BYTE_LENGTH => {
            let end = offset
                .checked_add(8)
                .ok_or(CoseError::ResourceLimitExceeded)?;
            let data = bytes.get(offset..end).ok_or(CoseError::Cbor)?;
            let value = u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            if value <= u64::from(u32::MAX) {
                return Err(CoseError::NonCanonicalCbor);
            }
            let len = usize::try_from(value).map_err(|_| CoseError::ResourceLimitExceeded)?;
            Ok((len, end))
        }
        _ => Err(CoseError::Cbor),
    }
}

fn parse_simple(bytes: &[u8], offset: usize, additional: u8) -> Result<usize, CoseError> {
    match additional {
        value if value < CBOR_ONE_BYTE_LENGTH => Ok(offset),
        CBOR_ONE_BYTE_LENGTH => offset
            .checked_add(1)
            .filter(|end| *end <= bytes.len())
            .ok_or(CoseError::Cbor),
        CBOR_TWO_BYTE_LENGTH => offset
            .checked_add(2)
            .filter(|end| *end <= bytes.len())
            .ok_or(CoseError::Cbor),
        CBOR_FOUR_BYTE_LENGTH => offset
            .checked_add(4)
            .filter(|end| *end <= bytes.len())
            .ok_or(CoseError::Cbor),
        CBOR_EIGHT_BYTE_LENGTH => offset
            .checked_add(8)
            .filter(|end| *end <= bytes.len())
            .ok_or(CoseError::Cbor),
        _ => Err(CoseError::Cbor),
    }
}

fn validate_tags(
    value: &Value,
    tag_policy: CborTagPolicy,
    depth: usize,
    is_root: bool,
) -> Result<(), CoseError> {
    if depth > MAX_CBOR_DEPTH {
        return Err(CoseError::ResourceLimitExceeded);
    }

    match value {
        Value::Tag(tag, inner) => {
            let root_cose_sign1 = is_root && tag_policy_allows_cose_sign1_root(tag_policy);
            if !root_cose_sign1 || *tag != COSE_SIGN1_TAG {
                return Err(CoseError::UnexpectedCborTag);
            }

            validate_tags(
                inner,
                CborTagPolicy::RejectAllTags,
                next_depth(depth)?,
                false,
            )
        }
        Value::Array(values) => {
            for item in values {
                validate_tags(item, tag_policy, next_depth(depth)?, false)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            reject_duplicate_map_keys(entries)?;
            for (key, value) in entries {
                let child_depth = next_depth(depth)?;
                validate_tags(key, tag_policy, child_depth, false)?;
                validate_tags(value, tag_policy, child_depth, false)?;
            }
            Ok(())
        }
        Value::Integer(_)
        | Value::Bytes(_)
        | Value::Float(_)
        | Value::Text(_)
        | Value::Bool(_)
        | Value::Null => Ok(()),
        _ => Err(CoseError::InvalidFormat),
    }
}

fn tag_policy_allows_cose_sign1_root(tag_policy: CborTagPolicy) -> bool {
    match tag_policy {
        #[cfg(feature = "cose-crypto")]
        CborTagPolicy::AllowCoseSign1Root => true,
        CborTagPolicy::RejectAllTags => false,
    }
}

fn reject_duplicate_map_keys(entries: &[(Value, Value)]) -> Result<(), CoseError> {
    for (index, (key, _)) in entries.iter().enumerate() {
        for (other_key, _) in entries.iter().skip(index.saturating_add(1)) {
            if key == other_key {
                return Err(CoseError::DuplicateMapLabel);
            }
        }
    }

    Ok(())
}

fn reject_duplicate_raw_key(
    bytes: &[u8],
    prior_ranges: &[(usize, usize)],
    key_start: usize,
    key_end: usize,
) -> Result<(), CoseError> {
    let key = bytes.get(key_start..key_end).ok_or(CoseError::Cbor)?;
    for (prior_start, prior_end) in prior_ranges {
        let prior = bytes.get(*prior_start..*prior_end).ok_or(CoseError::Cbor)?;
        if prior == key {
            return Err(CoseError::DuplicateMapLabel);
        }
    }

    Ok(())
}

fn next_depth(depth: usize) -> Result<usize, CoseError> {
    depth.checked_add(1).ok_or(CoseError::ResourceLimitExceeded)
}
