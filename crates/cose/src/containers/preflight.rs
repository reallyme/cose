// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::cbor::general::{self, Frame, MajorType};

use super::ContainerError;
use crate::{cbor_boundary, CoseError};

/// Check definite, preferred RFC 8949 serialization without requiring map order.
///
/// Codec owns framing, UTF-8, duplicate equality and encoding rules. This
/// preflight validates encoding rather than the complete ISO document grammar.
///
/// # Errors
/// Returns fixed encoding, duplicate, malformed, or resource-limit errors.
pub fn validate_preferred_cbor(encoded: &[u8]) -> Result<(), ContainerError> {
    validate_preferred_cbor_operation(encoded)
}

pub(crate) fn validate_preferred_cbor_operation(encoded: &[u8]) -> Result<(), ContainerError> {
    validate_with_width_policy(encoded, false)
}

pub(super) fn validate_issuer_mso_payload(
    encoded: &[u8],
    profile: super::ContainerProfile,
) -> Result<(), ContainerError> {
    validate_with_width_policy(encoded, profile == super::ContainerProfile::Iso2021)
}

fn validate_with_width_policy(encoded: &[u8], legacy_widths: bool) -> Result<(), ContainerError> {
    let item = general::validate_exact(
        encoded,
        cbor_boundary::preferred(legacy_widths)?,
        cbor_boundary::limits()?,
    )
    .map_err(cbor_boundary::error)?;
    validate_profile_arguments(item.frame(), 0, legacy_widths)
}

fn validate_profile_arguments(
    frame: &Frame<'_>,
    depth: usize,
    legacy_widths: bool,
) -> Result<(), CoseError> {
    if depth > cbor_boundary::MAX_ITEM_DEPTH {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let header = frame.header();
    if legacy_widths
        && !matches!(header.major_type(), MajorType::Tag | MajorType::Simple)
        && header.has_preferred_argument() == Some(false)
    {
        return Err(CoseError::NonCanonicalCbor);
    }
    if matches!(
        header.major_type(),
        MajorType::Array | MajorType::Map | MajorType::Tag
    ) {
        for child in frame.children().map_err(cbor_boundary::error)? {
            validate_profile_arguments(
                &child.map_err(cbor_boundary::error)?,
                depth
                    .checked_add(1)
                    .ok_or(CoseError::ResourceLimitExceeded)?,
                legacy_widths,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "iso2021_payload_tests.rs"]
mod iso2021_payload_tests;
