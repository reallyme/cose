// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Resource limits and deterministic CBOR boundary checks.

use std::collections::HashSet;

#[cfg(feature = "cose-crypto")]
use super::profile::validate_protected_header_bytes;
use crate::CoseError;

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
#[cfg(feature = "cose-crypto")]
const COSE_SIGN1_TAG: usize = 18;
#[cfg(feature = "cose-crypto")]
const COSE_ENCRYPT_TAG: usize = 96;
const MAX_CBOR_DEPTH: usize = 32;
const MAX_CBOR_COLLECTION_ITEMS: usize = 1_024;
#[cfg(feature = "cose-crypto")]
const MAX_COSE_HEADER_PARAMETERS: usize = 32;

pub(super) fn validate_cbor_bytes(
    bytes: &[u8],
    max_len: usize,
    role: CborItemRole,
) -> Result<(), CoseError> {
    if bytes.is_empty() {
        return Err(CoseError::Cbor);
    }

    if bytes.len() > max_len {
        return Err(CoseError::ResourceLimitExceeded);
    }

    let parsed_len = parse_cbor_item(bytes, 0, 0, role)?;
    if parsed_len == bytes.len() {
        Ok(())
    } else {
        Err(CoseError::Cbor)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CborItemRole {
    Normal,
    CoseKeyTop,
    #[cfg(feature = "cose-crypto")]
    CoseSign1Top,
    #[cfg(feature = "cose-crypto")]
    CoseSign1Body,
    #[cfg(feature = "cose-crypto")]
    CoseEncryptTop,
    #[cfg(feature = "cose-crypto")]
    CoseEncryptBody,
    #[cfg(feature = "cose-crypto")]
    CoseRecipientList,
    #[cfg(feature = "cose-crypto")]
    CoseRecipient,
    #[cfg(feature = "cose-crypto")]
    ProtectedHeaderMap,
    #[cfg(feature = "cose-crypto")]
    HeaderMap,
}

fn parse_cbor_item(
    bytes: &[u8],
    offset: usize,
    depth: usize,
    role: CborItemRole,
) -> Result<usize, CoseError> {
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

    #[cfg(feature = "cose-crypto")]
    if role == CborItemRole::ProtectedHeaderMap && major != CBOR_MAP_MAJOR {
        return Err(CoseError::InvalidFormat);
    }
    #[cfg(feature = "cose-crypto")]
    if matches!(
        role,
        CborItemRole::CoseEncryptBody
            | CborItemRole::CoseRecipientList
            | CborItemRole::CoseRecipient
    ) && major != CBOR_ARRAY_MAJOR
    {
        return Err(CoseError::InvalidFormat);
    }
    #[cfg(feature = "cose-crypto")]
    if role == CborItemRole::CoseEncryptTop && major != CBOR_ARRAY_MAJOR && major != CBOR_TAG_MAJOR
    {
        return Err(CoseError::InvalidFormat);
    }

    match major {
        CBOR_UINT_MAJOR | CBOR_NEGATIVE_INT_MAJOR => {
            read_argument(bytes, value_start, additional).map(|(_, next_offset)| next_offset)
        }
        CBOR_BYTES_MAJOR => {
            let (len, data_offset) = read_argument(bytes, value_start, additional)?;
            data_offset
                .checked_add(len)
                .filter(|end| *end <= bytes.len())
                .ok_or(CoseError::Cbor)
        }
        CBOR_TEXT_MAJOR => {
            let (len, data_offset) = read_argument(bytes, value_start, additional)?;
            let end = data_offset
                .checked_add(len)
                .filter(|end| *end <= bytes.len())
                .ok_or(CoseError::Cbor)?;
            let text = bytes.get(data_offset..end).ok_or(CoseError::Cbor)?;
            core::str::from_utf8(text).map_err(|_| CoseError::Cbor)?;
            Ok(end)
        }
        CBOR_ARRAY_MAJOR => {
            let (len, mut next_offset) = read_argument(bytes, value_start, additional)?;
            validate_collection_length(role, CBOR_ARRAY_MAJOR, len)?;
            let remaining = bytes
                .len()
                .checked_sub(next_offset)
                .ok_or(CoseError::Cbor)?;
            if len > remaining {
                return Err(CoseError::Cbor);
            }
            for index in 0..len {
                let child_depth = next_depth(depth)?;
                if protected_header_first_item(role) && index == 0 {
                    if let Some(end) =
                        parse_protected_header_bstr_if_present(bytes, next_offset, child_depth)?
                    {
                        next_offset = end;
                        continue;
                    }
                }
                let child_role = array_child_role(role, index);
                next_offset = parse_cbor_item(bytes, next_offset, child_depth, child_role)?;
            }
            Ok(next_offset)
        }
        CBOR_MAP_MAJOR => {
            let (len, mut next_offset) = read_argument(bytes, value_start, additional)?;
            validate_collection_length(role, CBOR_MAP_MAJOR, len)?;
            let remaining = bytes
                .len()
                .checked_sub(next_offset)
                .ok_or(CoseError::Cbor)?;
            if len > remaining / 2 {
                return Err(CoseError::Cbor);
            }
            let mut keys = HashSet::new();
            keys.try_reserve(len)
                .map_err(|_| CoseError::ResourceLimitExceeded)?;
            let mut previous_key: Option<&[u8]> = None;
            for _ in 0..len {
                let child_depth = next_depth(depth)?;
                let key_start = next_offset;
                let key_end =
                    parse_cbor_item(bytes, next_offset, child_depth, CborItemRole::Normal)?;
                let key = bytes.get(key_start..key_end).ok_or(CoseError::Cbor)?;
                // Container-valued keys can cause their encoded bytes to be
                // visited once per enclosing map. The global byte, item, and
                // depth limits deliberately bound that duplicate-key work.
                if !keys.insert(key) {
                    return Err(CoseError::DuplicateMapLabel);
                }
                if role == CborItemRole::CoseKeyTop
                    && previous_key.is_some_and(|previous| {
                        deterministic_key_order(previous, key) != core::cmp::Ordering::Less
                    })
                {
                    return Err(CoseError::NonCanonicalCbor);
                }
                previous_key = Some(key);
                next_offset = key_end;
                next_offset =
                    parse_cbor_item(bytes, next_offset, child_depth, CborItemRole::Normal)?;
            }
            Ok(next_offset)
        }
        CBOR_TAG_MAJOR => {
            let (tag, next_offset) = read_argument(bytes, value_start, additional)?;
            let child_role = tag_child_role(role, tag)?;
            parse_cbor_item(bytes, next_offset, next_depth(depth)?, child_role)
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
        CBOR_ONE_BYTE_LENGTH => {
            let value = *bytes.get(offset).ok_or(CoseError::Cbor)?;
            if value < CBOR_ONE_BYTE_LENGTH {
                return Err(CoseError::NonCanonicalCbor);
            }
            offset
                .checked_add(1)
                .filter(|end| *end <= bytes.len())
                .ok_or(CoseError::Cbor)
        }
        CBOR_TWO_BYTE_LENGTH | CBOR_FOUR_BYTE_LENGTH | CBOR_EIGHT_BYTE_LENGTH => {
            // COSE profiles do not require floating-point extension values.
            // Rejecting them avoids accepting encodings without enforcing the
            // RFC 8949 preferred-width and canonical-NaN requirements.
            Err(CoseError::NonCanonicalCbor)
        }
        _ => Err(CoseError::Cbor),
    }
}

fn deterministic_key_order(left: &[u8], right: &[u8]) -> core::cmp::Ordering {
    // RFC 8949 core deterministic encoding sorts map keys bytewise by their
    // deterministic encodings. Length-first ordering is the distinct legacy
    // alternative in RFC 8949 Section 4.2.3 and must not be used for the core
    // deterministic profile that stabilizes COSE_Key-derived identifiers.
    left.cmp(right)
}

fn validate_collection_length(role: CborItemRole, major: u8, len: usize) -> Result<(), CoseError> {
    if len > MAX_CBOR_COLLECTION_ITEMS {
        return Err(CoseError::ResourceLimitExceeded);
    }

    #[cfg(not(feature = "cose-crypto"))]
    let _ = (role, major);

    #[cfg(feature = "cose-crypto")]
    {
        if matches!(
            role,
            CborItemRole::ProtectedHeaderMap | CborItemRole::HeaderMap
        ) && major == CBOR_MAP_MAJOR
            && len > MAX_COSE_HEADER_PARAMETERS
        {
            return Err(CoseError::ResourceLimitExceeded);
        }
        if matches!(
            role,
            CborItemRole::CoseSign1Top | CborItemRole::CoseSign1Body
        ) && (major != CBOR_ARRAY_MAJOR || len != 4)
        {
            return Err(CoseError::InvalidFormat);
        }
        if matches!(
            role,
            CborItemRole::CoseEncryptTop | CborItemRole::CoseEncryptBody
        ) && (major != CBOR_ARRAY_MAJOR || len != 4)
        {
            return Err(CoseError::InvalidFormat);
        }
        if role == CborItemRole::CoseRecipientList && (major != CBOR_ARRAY_MAJOR || len != 1) {
            return Err(CoseError::InvalidRecipient);
        }
        if role == CborItemRole::CoseRecipient && (major != CBOR_ARRAY_MAJOR || len != 3) {
            return Err(CoseError::InvalidRecipient);
        }
    }

    Ok(())
}

fn tag_child_role(role: CborItemRole, tag: usize) -> Result<CborItemRole, CoseError> {
    #[cfg(not(feature = "cose-crypto"))]
    let _ = tag;

    match role {
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseSign1Top if tag == COSE_SIGN1_TAG => Ok(CborItemRole::CoseSign1Body),
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseEncryptTop if tag == COSE_ENCRYPT_TAG => {
            Ok(CborItemRole::CoseEncryptBody)
        }
        _ => Err(CoseError::UnexpectedCborTag),
    }
}

fn protected_header_first_item(role: CborItemRole) -> bool {
    match role {
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseSign1Top
        | CborItemRole::CoseSign1Body
        | CborItemRole::CoseEncryptTop
        | CborItemRole::CoseEncryptBody
        | CborItemRole::CoseRecipient => true,
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseRecipientList
        | CborItemRole::ProtectedHeaderMap
        | CborItemRole::HeaderMap => false,
        CborItemRole::Normal | CborItemRole::CoseKeyTop => false,
    }
}

fn array_child_role(role: CborItemRole, index: usize) -> CborItemRole {
    #[cfg(not(feature = "cose-crypto"))]
    let _ = index;

    match role {
        CborItemRole::CoseKeyTop => CborItemRole::Normal,
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseEncryptTop | CborItemRole::CoseEncryptBody if index == 3 => {
            CborItemRole::CoseRecipientList
        }
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseSign1Top
        | CborItemRole::CoseSign1Body
        | CborItemRole::CoseEncryptTop
        | CborItemRole::CoseEncryptBody
        | CborItemRole::CoseRecipient
            if index == 1 =>
        {
            CborItemRole::HeaderMap
        }
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseRecipientList => CborItemRole::CoseRecipient,
        _ => CborItemRole::Normal,
    }
}

#[cfg(feature = "cose-crypto")]
fn parse_protected_header_bstr_if_present(
    bytes: &[u8],
    offset: usize,
    depth: usize,
) -> Result<Option<usize>, CoseError> {
    if depth > MAX_CBOR_DEPTH {
        return Err(CoseError::ResourceLimitExceeded);
    }

    let first = *bytes.get(offset).ok_or(CoseError::Cbor)?;
    let major = first >> CBOR_MAJOR_TYPE_SHIFT;
    if major != CBOR_BYTES_MAJOR {
        return Ok(None);
    }

    let additional = first & CBOR_ADDITIONAL_INFO_MASK;
    let value_start = offset
        .checked_add(1)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    if additional == CBOR_INDEFINITE_ADDITIONAL_INFO {
        return Err(CoseError::NonCanonicalCbor);
    }

    let (len, data_offset) = read_argument(bytes, value_start, additional)?;
    let end = data_offset
        .checked_add(len)
        .filter(|candidate| *candidate <= bytes.len())
        .ok_or(CoseError::Cbor)?;
    let protected = bytes.get(data_offset..end).ok_or(CoseError::Cbor)?;
    validate_protected_header_bytes(protected)?;

    Ok(Some(end))
}

#[cfg(not(feature = "cose-crypto"))]
fn parse_protected_header_bstr_if_present(
    _bytes: &[u8],
    _offset: usize,
    _depth: usize,
) -> Result<Option<usize>, CoseError> {
    Ok(None)
}

fn next_depth(depth: usize) -> Result<usize, CoseError> {
    depth.checked_add(1).ok_or(CoseError::ResourceLimitExceeded)
}
