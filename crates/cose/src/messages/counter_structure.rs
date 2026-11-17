// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{bounded, counter_target::Target};
use crate::CoseError;
use reallyme_codec::cbor::general::ValueRef;
use reallyme_cose_proto::SecretBytes;

pub(super) fn encode(
    target: &Target<'_>,
    sign_protected: Option<&[u8]>,
    aad: &[u8],
) -> Result<SecretBytes, CoseError> {
    let context = match (sign_protected.is_some(), target.other.is_some()) {
        (true, false) => "CounterSignature",
        (false, false) => "CounterSignature0",
        (true, true) => "CounterSignatureV2",
        (false, true) => "CounterSignature0V2",
    };
    let other = target.other.map(|value| [ValueRef::Bytes(value)]);
    let mut fields = Vec::new();
    fields
        .try_reserve_exact(6)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    fields.push(ValueRef::Text(context));
    fields.push(ValueRef::Bytes(target.protected));
    if let Some(protected) = sign_protected {
        fields.push(ValueRef::Bytes(protected));
    }
    fields.push(ValueRef::Bytes(aad));
    fields.push(ValueRef::Bytes(target.payload));
    if let Some(other) = &other {
        fields.push(ValueRef::Array(other));
    }
    let value = ValueRef::Array(&fields);
    bounded::encode(&value)
}
