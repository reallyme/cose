// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{read_headers, read_message};
use crate::api::contract::CoseRecipientAlgorithm as Algorithm;
use crate::CoseError;
use reallyme_codec::cbor::general::{Frame, MajorType};

pub(super) const MAX_RECIPIENTS: usize = 32;
pub(super) const MAX_RECIPIENT_DEPTH: usize = 4;

pub(super) fn allowlist(allowed: &[buffa::EnumValue<Algorithm>]) -> Result<(), CoseError> {
    if allowed.is_empty() || allowed.len() > 4 {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    for (index, value) in allowed.iter().enumerate() {
        if !matches!(
            value.as_known(),
            Some(Algorithm::Direct | Algorithm::A128kw | Algorithm::A192kw | Algorithm::A256kw)
        ) {
            return Err(CoseError::UnsupportedAlgorithm);
        }
        if allowed
            .get(..index)
            .ok_or(CoseError::InvalidFormat)?
            .contains(value)
        {
            return Err(CoseError::InvalidFormat);
        }
    }
    Ok(())
}
pub(super) fn algorithm(
    headers: &read_headers::Headers<'_>,
    allowed: &[buffa::EnumValue<Algorithm>],
) -> Result<Algorithm, CoseError> {
    let algorithm = match headers.algorithm {
        Some(-6) => Algorithm::Direct,
        Some(-3) => Algorithm::A128kw,
        Some(-4) => Algorithm::A192kw,
        Some(-5) => Algorithm::A256kw,
        _ => return Err(CoseError::UnsupportedAlgorithm),
    };
    if !allowed.iter().any(|value| *value == algorithm) {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    if !headers.protected.is_empty() {
        return Err(CoseError::InvalidRecipient);
    }
    Ok(algorithm)
}
pub(super) fn count(total: &mut usize, depth: usize) -> Result<(), CoseError> {
    if depth > MAX_RECIPIENT_DEPTH {
        return Err(CoseError::ResourceLimitExceeded);
    }
    *total = total
        .checked_add(1)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    if *total > MAX_RECIPIENTS {
        return Err(CoseError::ResourceLimitExceeded);
    }
    Ok(())
}

// Validate framing for the entire tree without authorizing unselected algorithms.
// A caller-selected supported recipient remains usable beside an unsupported one.
pub(super) fn validate_tree(
    frame: &Frame<'_>,
    depth: usize,
    total: &mut usize,
) -> Result<(), CoseError> {
    let recipients = read_message::children(frame, MajorType::Array, MAX_RECIPIENTS)?;
    if recipients.is_empty() {
        return Err(CoseError::InvalidRecipient);
    }
    for recipient in &recipients {
        count(total, depth)?;
        let fields = read_message::children(recipient, MajorType::Array, 4)?;
        if !matches!(fields.len(), 3 | 4) {
            return Err(CoseError::InvalidRecipient);
        }
        let protected = fields
            .first()
            .ok_or(CoseError::InvalidRecipient)?
            .as_bytes()
            .map_err(crate::cbor_boundary::error)?;
        let unprotected = fields.get(1).ok_or(CoseError::InvalidRecipient)?;
        if protected.len() > read_message::MAX_HEADER_BYTES
            || unprotected.received_bytes().len() > read_message::MAX_HEADER_BYTES
        {
            return Err(CoseError::ResourceLimitExceeded);
        }
        let parameters = read_message::children(
            unprotected,
            MajorType::Map,
            read_message::MAX_HEADER_PARAMETERS,
        )?;
        if recipients.len() != 1
            && super::validate_key_map::parameter(&parameters, 1)?
                .is_some_and(|value| read_headers::integer(value).ok() == Some(-6))
        {
            return Err(CoseError::InvalidRecipient);
        }
        fields
            .get(2)
            .ok_or(CoseError::InvalidRecipient)?
            .as_bytes()
            .map_err(crate::cbor_boundary::error)?;
        if let Some(children) = fields.get(3) {
            validate_tree(
                children,
                depth
                    .checked_add(1)
                    .ok_or(CoseError::ResourceLimitExceeded)?,
                total,
            )?;
        }
    }
    Ok(())
}
