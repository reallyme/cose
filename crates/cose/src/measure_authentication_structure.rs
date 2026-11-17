// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::CoseError;

const ARRAY_HEADER_BYTES: usize = 1;
const CONTEXT_TEXT_HEADER_BYTES: usize = 1;
const CBOR_DIRECT_ARGUMENT_MAX: usize = 23;
const CBOR_ONE_BYTE_ARGUMENT_MAX: usize = 0xff;
const CBOR_TWO_BYTE_ARGUMENT_MAX: usize = 0xffff;

pub(super) fn authentication_structure_size(
    context_bytes: usize,
    protected_bytes: usize,
    external_aad_bytes: usize,
    payload_bytes: usize,
    max_output_bytes: usize,
) -> Result<usize, CoseError> {
    // Account for every CBOR prefix before reserving output. Summing only the
    // caller's byte slices would permit the encoded structure to exceed its
    // budget at each byte-string length boundary.
    let size = ARRAY_HEADER_BYTES
        .checked_add(CONTEXT_TEXT_HEADER_BYTES)
        .and_then(|size| size.checked_add(context_bytes))
        .and_then(|size| checked_bstr_size(size, protected_bytes))
        .and_then(|size| checked_bstr_size(size, external_aad_bytes))
        .and_then(|size| checked_bstr_size(size, payload_bytes))
        .ok_or(CoseError::ResourceLimitExceeded)?;
    if size > max_output_bytes {
        return Err(CoseError::ResourceLimitExceeded);
    }
    Ok(size)
}

pub(super) fn checked_bstr_size(current: usize, payload_len: usize) -> Option<usize> {
    current
        .checked_add(cbor_length_header_size(payload_len))?
        .checked_add(payload_len)
}

fn cbor_length_header_size(length: usize) -> usize {
    if length <= CBOR_DIRECT_ARGUMENT_MAX {
        1
    } else if length <= CBOR_ONE_BYTE_ARGUMENT_MAX {
        2
    } else if length <= CBOR_TWO_BYTE_ARGUMENT_MAX {
        3
    } else if u32::try_from(length).is_ok() {
        5
    } else {
        9
    }
}
