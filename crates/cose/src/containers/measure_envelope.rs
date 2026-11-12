// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ContainerError, ContainerErrorReason as Reason};
use crate::build_authentication_structure::encoded_bstr_size;

const ARRAY_OF_FOUR_HEADER_BYTES: usize = 1;
const SIGN1_TAG_HEADER_BYTES: usize = 1;
const CBOR_NULL_BYTES: usize = 1;

pub(super) fn measure_envelope(
    protected_bytes: usize,
    unprotected_bytes: usize,
    payload_bytes: Option<usize>,
    signature_bytes: usize,
    tagged: bool,
) -> Result<usize, ContainerError> {
    let tag_bytes = if tagged { SIGN1_TAG_HEADER_BYTES } else { 0 };
    let payload_bytes = match payload_bytes {
        Some(bytes) => encoded_bstr_size(bytes)?,
        None => CBOR_NULL_BYTES,
    };
    let protected_bytes = encoded_bstr_size(protected_bytes)?;
    let signature_bytes = encoded_bstr_size(signature_bytes)?;
    ARRAY_OF_FOUR_HEADER_BYTES
        .checked_add(tag_bytes)
        .and_then(|size| size.checked_add(protected_bytes))
        .and_then(|size| size.checked_add(unprotected_bytes))
        .and_then(|size| size.checked_add(payload_bytes))
        .and_then(|size| size.checked_add(signature_bytes))
        .ok_or(Reason::Limit.into())
}
