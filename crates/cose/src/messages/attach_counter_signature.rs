// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{bounded, counter_signature, counter_target, read_message, validate_key_map::label};
use crate::api::contract::{
    self as contract, __buffa::oneof::cose_counter_signature_attach_request::Signature,
};
use crate::CoseError;
use reallyme_codec::cbor::general::{MajorType, MapEntry, ValueRef};

pub(crate) fn attach(
    request: &contract::CoseCounterSignatureAttachRequest,
) -> Result<contract::CoseMessageCreateResult, CoseError> {
    let target =
        counter_target::parse(request.target.as_option().ok_or(CoseError::InvalidFormat)?)?;
    let source = request.signature.as_ref().ok_or(CoseError::InvalidFormat)?;
    let full = match source {
        Signature::Full(encoded) => Some(counter_signature::full(
            encoded,
            contract::CoseEnvelopePolicy::Either.into(),
        )?),
        Signature::Abbreviated(_) => None,
    };
    let abbreviated = match source {
        Signature::Abbreviated(encoded) => {
            let value = bounded::validated(encoded)?;
            if value
                .frame()
                .as_bytes()
                .map_err(crate::cbor_boundary::error)?
                .is_empty()
            {
                return Err(CoseError::InvalidSignatureEncoding);
            }
            Some(bounded::frame(encoded)?)
        }
        Signature::Full(_) => None,
    };
    let mut full_values = Vec::new();
    full_values
        .try_reserve_exact(3)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    if let Some(full) = &full {
        for frame in full {
            full_values.push(ValueRef::Received(frame));
        }
    }
    let wanted = if full.is_some() {
        counter_target::FULL_HEADER
    } else {
        counter_target::ABBREVIATED_HEADER
    };
    let existing = counter_target::header(&target, wanted)?;
    if abbreviated.is_some() && existing.is_some() {
        return Err(CoseError::DuplicateMapLabel);
    }
    let old = existing
        .as_ref()
        .filter(|_| full.is_some())
        .map(counter_signature::collection)
        .transpose()?
        .unwrap_or_default();
    if old.len() >= read_message::MAX_SIGNATURES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let mut counters = Vec::new();
    counters
        .try_reserve_exact(
            old.len()
                .checked_add(1)
                .ok_or(CoseError::ResourceLimitExceeded)?,
        )
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for frame in &old {
        counters.push(ValueRef::Received(frame));
    }
    if full.is_some() && existing.is_some() {
        counters.push(ValueRef::Array(&full_values));
    }
    let replacement = if let Some(frame) = &abbreviated {
        ValueRef::Received(frame)
    } else if existing.is_some() {
        ValueRef::Array(&counters)
    } else {
        ValueRef::Array(&full_values)
    };
    let mut replacement = Some(replacement);
    let unprotected = target.fields.get(1).ok_or(CoseError::InvalidFormat)?;
    let fields = read_message::children(
        unprotected,
        MajorType::Map,
        read_message::MAX_HEADER_PARAMETERS,
    )?;
    let capacity = fields
        .as_chunks::<2>()
        .0
        .len()
        .checked_add(usize::from(existing.is_none()))
        .ok_or(CoseError::ResourceLimitExceeded)?;
    if capacity > read_message::MAX_HEADER_PARAMETERS {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(capacity)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for [key, value] in fields.as_chunks::<2>().0 {
        let value = if label(key)? == Some(wanted) {
            replacement.take().ok_or(CoseError::DuplicateMapLabel)?
        } else {
            ValueRef::Received(value)
        };
        entries.push(MapEntry::new(ValueRef::Received(key), value));
    }
    if let Some(value) = replacement.take() {
        entries.push(MapEntry::new(
            ValueRef::Unsigned(u64::try_from(wanted).map_err(|_| CoseError::InvalidFormat)?),
            value,
        ));
    }
    let map = ValueRef::Map(&entries);
    let unprotected = bounded::encode_with_limit(&map, read_message::MAX_HEADER_BYTES)?;
    let unprotected = bounded::frame(&unprotected)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(target.fields.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for (index, frame) in target.fields.iter().enumerate() {
        values.push(ValueRef::Received(if index == 1 {
            &unprotected
        } else {
            frame
        }));
    }
    let body = ValueRef::Array(&values);
    let value = if let Some(tag) = target.tag {
        ValueRef::Tag(tag, &body)
    } else {
        ValueRef::Array(&values)
    };
    Ok(contract::CoseMessageCreateResult {
        encoded: bounded::encode(&value)?,
    })
}

pub(crate) fn valid_created(result: &contract::CoseMessageCreateResult) -> bool {
    counter_signature::valid_created(result)
}
