// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wipe sensitive protobuf fields before replacement can release their storage.

use buffa::{bytes::Buf, DecodeError};
use zeroize::{Zeroize, Zeroizing};

pub(crate) fn merge_bytes(value: &mut Vec<u8>, buf: &mut impl Buf) -> Result<(), DecodeError> {
    // Protobuf singular fields use the last occurrence. Buffa clears the old
    // length before copying, so a growing replacement can free unwiped bytes.
    let retain_allocation = value.len() == value.capacity();
    value.zeroize();
    // A shrinking replacement must not keep a large capacity across many
    // tiny fields: wiping that capacity on every occurrence is quadratic.
    // Release spare capacity after wiping, before decoding the next field.
    if !retain_allocation {
        *value = Vec::new();
    }
    buffa::types::merge_bytes(value, buf)
}

pub(crate) fn merge_string(value: &mut String, buf: &mut impl Buf) -> Result<(), DecodeError> {
    // Keep malformed UTF-8 under a wipe owner too, including noncontiguous Buf
    // inputs, for which a string decoder must first copy the unvalidated bytes.
    let retain_allocation = value.len() == value.capacity();
    value.zeroize();
    if !retain_allocation {
        *value = String::new();
    }
    // Slice-backed protobuf decoding needs no temporary allocation: Buffa
    // validates contiguous UTF-8 before copying it into the wiped destination.
    if buf.chunk().len() == buf.remaining() {
        return buffa::types::merge_string(value, buf);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    buffa::types::merge_bytes(&mut bytes, buf)?;
    let text = core::str::from_utf8(&bytes).map_err(|_| DecodeError::InvalidUtf8)?;
    value.push_str(text);
    Ok(())
}

#[cfg(test)]
#[path = "merge_sensitive_tests.rs"]
mod tests;
