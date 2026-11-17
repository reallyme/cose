// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{bounded, read_headers, read_message, recipient, wrap_key};
use crate::{api::contract::CoseRecipientAlgorithm as Algorithm, CoseError};
use reallyme_codec::cbor::general::{Frame, MajorType};
use reallyme_cose_proto::SecretBytes;

pub(super) fn open(
    recipients: &Frame<'_>,
    path: &[u32],
    leaf_key: &[u8],
    allowed: &[buffa::EnumValue<Algorithm>],
    expected: usize,
) -> Result<SecretBytes, CoseError> {
    let (index, path) = path.split_first().ok_or(CoseError::InvalidRecipient)?;
    let recipients =
        read_message::children(recipients, MajorType::Array, recipient::MAX_RECIPIENTS)?;
    let selected = recipients
        .get(usize::try_from(*index).map_err(|_| CoseError::InvalidRecipient)?)
        .ok_or(CoseError::InvalidRecipient)?;
    let fields = read_message::children(selected, MajorType::Array, 4)?;
    let protected = fields
        .first()
        .ok_or(CoseError::InvalidRecipient)?
        .as_bytes()
        .map_err(crate::cbor_boundary::error)?;
    let headers = read_headers::recipient(
        protected,
        fields
            .get(1)
            .ok_or(CoseError::InvalidRecipient)?
            .received_bytes(),
    )?;
    let algorithm = recipient::algorithm(&headers, allowed)?;
    let ciphertext = fields
        .get(2)
        .ok_or(CoseError::InvalidRecipient)?
        .as_bytes()
        .map_err(crate::cbor_boundary::error)?;
    if algorithm == Algorithm::Direct {
        if recipients.len() != 1 || fields.len() != 3 || !ciphertext.is_empty() || !path.is_empty()
        {
            return Err(CoseError::InvalidRecipient);
        }
        if leaf_key.len() != expected {
            return Err(CoseError::InvalidKeyMaterial);
        }
        return bounded::copy(leaf_key);
    }
    let kek = if let Some(children) = fields.get(3) {
        open(
            children,
            path,
            leaf_key,
            allowed,
            wrap_key::length(algorithm)?,
        )?
    } else {
        if !path.is_empty() {
            return Err(CoseError::InvalidRecipient);
        }
        bounded::copy(leaf_key)?
    };
    wrap_key::unwrap(algorithm, &kek, ciphertext, expected)
}
