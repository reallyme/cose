// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::cbor::general::{self, Frame, Item, LengthPolicy, Limits, Profile, ValueRef};
use reallyme_cose_proto::SecretBytes;
use zeroize::Zeroizing;

use crate::{cbor_boundary, CoseError};

pub(super) const MAX_MESSAGE_BYTES: usize = 1_048_576;
pub(super) const MAX_KEY_SET_MEMBERS: usize = 64;

pub(super) fn limits() -> Result<Limits, CoseError> {
    cbor_boundary::limits()?
        .with_input_bytes(MAX_MESSAGE_BYTES)
        .and_then(|limits| limits.with_output_bytes(MAX_MESSAGE_BYTES))
        .map_err(cbor_boundary::error)
}

pub(super) fn frame(encoded: &[u8]) -> Result<Frame<'_>, CoseError> {
    if encoded.len() > MAX_MESSAGE_BYTES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    general::frame_exact(encoded, limits()?, LengthPolicy::DefiniteOnly)
        .map_err(cbor_boundary::error)
}

pub(super) fn validated(encoded: &[u8]) -> Result<Item<'_>, CoseError> {
    general::validate_exact(encoded, Profile::preferred(), limits()?).map_err(cbor_boundary::error)
}

pub(super) fn copy(bytes: &[u8]) -> Result<SecretBytes, CoseError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let mut owner = Zeroizing::new(Vec::new());
    owner
        .try_reserve_exact(bytes.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    owner.extend_from_slice(bytes);
    Ok(core::mem::take(&mut *owner).into())
}

pub(super) fn encode(value: &ValueRef<'_>) -> Result<SecretBytes, CoseError> {
    let encoded =
        general::encode(value, Profile::preferred(), limits()?).map_err(cbor_boundary::error)?;
    copy(encoded.as_bytes())
}
