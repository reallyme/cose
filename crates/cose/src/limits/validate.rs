// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! COSE grammar admission over the shared codec's exact borrowed CBOR receipts.

use reallyme_codec::cbor::general::{self, Frame, MajorType};

#[cfg(feature = "cose-crypto")]
use super::profile::validate_protected_header_bytes;
use super::profile::{next_depth, validate_item_depth};
use crate::{cbor_boundary, CoseError};

#[cfg(feature = "cose-crypto")]
const CBOR_ARRAY_MAJOR: u8 = 4;
#[cfg(feature = "cose-crypto")]
const CBOR_MAP_MAJOR: u8 = 5;
#[cfg(feature = "cose-crypto")]
const MAX_COSE_HEADER_PARAMETERS: usize = 32;
#[cfg(feature = "cose-crypto")]
const COSE_SIGN1_TAG: u64 = 18;
#[cfg(feature = "cose-crypto")]
const COSE_MAC0_TAG: u64 = 17;
#[cfg(feature = "cose-crypto")]
const COSE_ENCRYPT_TAG: u64 = 96;

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
    let consumed = parse_cbor_item(bytes, 0, 0, role)?;
    if consumed != bytes.len() {
        return Err(CoseError::Cbor);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub(super) enum CborItemRole {
    Normal,
    CoseKeyTop,
    CoseKeyValue,
    #[cfg(feature = "cose-crypto")]
    CoseIsoKeyTop,
    #[cfg(feature = "cose-crypto")]
    CoseSign1Top,
    #[cfg(feature = "cose-crypto")]
    CoseSign1Body,
    #[cfg(feature = "cose-crypto")]
    CoseMac0Top,
    #[cfg(feature = "cose-crypto")]
    CoseMac0Body,
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
    validate_item_depth(depth)?;
    let input = bytes.get(offset..).ok_or(CoseError::Cbor)?;
    // Keep early shape failures deterministic even if an invalid declared
    // array has no body. Codec remains the sole decoder of the header.
    let header = general::read_header_prefix(input)
        .map_err(|error| cbor_boundary::primitive_error(error, input))?;
    validate_role_header(&header, role)?;
    let profile = cbor_boundary::preferred(false)?
        .with_floats(general::FloatPolicy::Reject)
        .with_map_ordering(
            if matches!(role, CborItemRole::CoseKeyTop | CborItemRole::CoseKeyValue) {
                general::MapOrdering::Bytewise
            } else {
                general::MapOrdering::Received
            },
        );
    let (item, _) = general::validate_prefix(input, profile, cbor_boundary::limits()?)
        .map_err(|error| cbor_boundary::primitive_error(error, input))?;
    validate_role(item.frame(), depth, role)?;
    offset
        .checked_add(item.frame().received_bytes().len())
        .ok_or(CoseError::ResourceLimitExceeded)
}

// Generic CBOR has already been validated by codec. This walk checks only the
// COSE grammar, profile exclusions needed by coset's value model, and embedded
// protected maps. A byte string remains opaque except in the protected slot.
fn validate_role(frame: &Frame<'_>, depth: usize, role: CborItemRole) -> Result<(), CoseError> {
    validate_item_depth(depth)?;
    let header = frame.header();
    validate_role_header(header, role)?;
    match header.major_type() {
        MajorType::Array | MajorType::Map => {
            for (index, child) in frame.children().map_err(cbor_boundary::error)?.enumerate() {
                let child = child.map_err(cbor_boundary::error)?;
                let child_depth = next_depth(depth)?;
                if header.major_type() == MajorType::Array {
                    #[cfg(feature = "cose-crypto")]
                    if index == 0
                        && protected_header_first_item(role)
                        && child.header().major_type() == MajorType::Bytes
                    {
                        validate_item_depth(child_depth)?;
                        validate_protected_header_bytes(
                            child.as_bytes().map_err(cbor_boundary::error)?,
                        )?;
                        continue;
                    }
                    validate_role(&child, child_depth, array_child_role(role, index))?;
                } else {
                    let child_role =
                        if matches!(role, CborItemRole::CoseKeyTop | CborItemRole::CoseKeyValue) {
                            CborItemRole::CoseKeyValue
                        } else {
                            CborItemRole::Normal
                        };
                    validate_role(&child, child_depth, child_role)?;
                }
            }
        }
        MajorType::Tag => {
            let role = tag_child_role(role, header.argument().ok_or(CoseError::Cbor)?)?;
            let mut children = frame.children().map_err(cbor_boundary::error)?;
            let child = children
                .next()
                .ok_or(CoseError::Cbor)?
                .map_err(cbor_boundary::error)?;
            validate_role(&child, next_depth(depth)?, role)?;
        }
        MajorType::Simple
            if !matches!(frame.simple_value().map_err(cbor_boundary::error)?, 20..=22) =>
        {
            return Err(CoseError::Cbor)
        }
        _ => {}
    }
    Ok(())
}

fn validate_role_header(header: &general::Header<'_>, role: CborItemRole) -> Result<(), CoseError> {
    let major = cbor_boundary::major_code(header.major_type())?;
    #[cfg(feature = "cose-crypto")]
    {
        if matches!(
            role,
            CborItemRole::ProtectedHeaderMap | CborItemRole::CoseIsoKeyTop
        ) && major != CBOR_MAP_MAJOR
        {
            return Err(CoseError::InvalidFormat);
        }
        if matches!(
            role,
            CborItemRole::CoseEncryptBody
                | CborItemRole::CoseMac0Body
                | CborItemRole::CoseRecipientList
                | CborItemRole::CoseRecipient
        ) && major != CBOR_ARRAY_MAJOR
        {
            return Err(CoseError::InvalidFormat);
        }
        if matches!(
            role,
            CborItemRole::CoseEncryptTop | CborItemRole::CoseMac0Top
        ) && !matches!(header.major_type(), MajorType::Array | MajorType::Tag)
        {
            return Err(CoseError::InvalidFormat);
        }
    }
    if matches!(header.major_type(), MajorType::Array | MajorType::Map) {
        if let Some(count) = header.argument() {
            validate_collection_length(
                role,
                major,
                usize::try_from(count).map_err(|_| CoseError::ResourceLimitExceeded)?,
            )?;
        }
    }
    Ok(())
}

fn validate_collection_length(role: CborItemRole, major: u8, len: usize) -> Result<(), CoseError> {
    if len > cbor_boundary::MAX_COLLECTION_ENTRIES {
        return Err(CoseError::ResourceLimitExceeded);
    }

    #[cfg(not(feature = "cose-crypto"))]
    let _ = (role, major);

    #[cfg(feature = "cose-crypto")]
    {
        if matches!(
            role,
            CborItemRole::ProtectedHeaderMap
                | CborItemRole::HeaderMap
                | CborItemRole::CoseIsoKeyTop
        ) && major == CBOR_MAP_MAJOR
            && len > MAX_COSE_HEADER_PARAMETERS
        {
            return Err(CoseError::ResourceLimitExceeded);
        }
        if matches!(
            role,
            CborItemRole::CoseSign1Top
                | CborItemRole::CoseSign1Body
                | CborItemRole::CoseMac0Top
                | CborItemRole::CoseMac0Body
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

fn tag_child_role(role: CborItemRole, tag: u64) -> Result<CborItemRole, CoseError> {
    #[cfg(not(feature = "cose-crypto"))]
    let _ = tag;

    match role {
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseSign1Top if tag == COSE_SIGN1_TAG => Ok(CborItemRole::CoseSign1Body),
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseMac0Top if tag == COSE_MAC0_TAG => Ok(CborItemRole::CoseMac0Body),
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseEncryptTop if tag == COSE_ENCRYPT_TAG => {
            Ok(CborItemRole::CoseEncryptBody)
        }
        _ => Err(CoseError::UnexpectedCborTag),
    }
}

#[cfg(feature = "cose-crypto")]
fn protected_header_first_item(role: CborItemRole) -> bool {
    match role {
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseSign1Top
        | CborItemRole::CoseSign1Body
        | CborItemRole::CoseMac0Top
        | CborItemRole::CoseMac0Body
        | CborItemRole::CoseEncryptTop
        | CborItemRole::CoseEncryptBody
        | CborItemRole::CoseRecipient => true,
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseRecipientList
        | CborItemRole::CoseIsoKeyTop
        | CborItemRole::ProtectedHeaderMap
        | CborItemRole::HeaderMap => false,
        CborItemRole::Normal | CborItemRole::CoseKeyTop | CborItemRole::CoseKeyValue => false,
    }
}

fn array_child_role(role: CborItemRole, index: usize) -> CborItemRole {
    #[cfg(not(feature = "cose-crypto"))]
    let _ = index;

    match role {
        CborItemRole::CoseKeyTop | CborItemRole::CoseKeyValue => CborItemRole::CoseKeyValue,
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseEncryptTop | CborItemRole::CoseEncryptBody if index == 3 => {
            CborItemRole::CoseRecipientList
        }
        #[cfg(feature = "cose-crypto")]
        CborItemRole::CoseSign1Top
        | CborItemRole::CoseSign1Body
        | CborItemRole::CoseMac0Top
        | CborItemRole::CoseMac0Body
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

#[cfg(all(kani, feature = "cose-crypto"))]
#[path = "verify_cbor_limits_proof_tests.rs"]
mod verification;
