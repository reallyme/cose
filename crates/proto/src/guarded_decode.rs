// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Allocate the final wipe owner before reading a bounded field, even in chunks.

use buffa::{bytes::Buf, DecodeError, FieldPayload};
use zeroize::Zeroizing;

// A single field cannot exceed the executable protobuf envelope ceiling.
pub(crate) const MAX_FIELD_BYTES: usize = 2 * 1024 * 1024;

pub(crate) fn copy(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
    copy_with_limit(bytes, MAX_FIELD_BYTES)
}

pub(crate) fn copy_with_limit(
    bytes: &[u8],
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
    if bytes.len() > maximum {
        return Err(DecodeError::MessageTooLarge);
    }
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| DecodeError::MessageTooLarge)?;
    output.extend_from_slice(bytes);
    Ok(output)
}

pub(crate) fn read(
    payload: &mut FieldPayload<impl Buf>,
) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
    if payload.remaining() > MAX_FIELD_BYTES {
        return Err(DecodeError::MessageTooLarge);
    }
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(payload.remaining())
        .map_err(|_| DecodeError::MessageTooLarge)?;
    while payload.has_remaining() {
        let chunk = payload.chunk();
        output.extend_from_slice(chunk);
        let length = chunk.len();
        payload.advance(length);
    }
    Ok(output)
}

pub(crate) fn text(mut bytes: Zeroizing<Vec<u8>>) -> Result<String, DecodeError> {
    core::str::from_utf8(&bytes).map_err(|_| DecodeError::InvalidUtf8)?;
    match String::from_utf8(core::mem::take(&mut *bytes)) {
        Ok(value) => Ok(value),
        Err(error) => {
            // Retain ownership even if a future conversion changes validation.
            let _rejected = Zeroizing::new(error.into_bytes());
            Err(DecodeError::InvalidUtf8)
        }
    }
}
