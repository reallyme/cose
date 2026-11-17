// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{bounded, create_recipients, open_recipient, read_headers, read_message, recipient};
use crate::api::contract::{self as contract, CoseErrorReason};
use crate::mac0::CoseMacVerifier;
use crate::{CoseError, CoseMacAlgorithm, CoseMacKey};
use reallyme_codec::cbor::general::ValueRef;

fn authorize(
    algorithm: buffa::EnumValue<contract::CoseMacAlgorithm>,
    allowed: &[buffa::EnumValue<contract::CoseMacAlgorithm>],
    received: Option<i64>,
) -> Result<CoseMacAlgorithm, CoseError> {
    if allowed.is_empty() || allowed.len() > 4 {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    for (index, value) in allowed.iter().enumerate() {
        CoseMacAlgorithm::try_from(*value)?;
        if allowed
            .get(..index)
            .ok_or(CoseError::InvalidFormat)?
            .contains(value)
        {
            return Err(CoseError::InvalidFormat);
        }
    }
    let value = CoseMacAlgorithm::try_from(algorithm)?;
    if received != Some(value.cose_id()) || !allowed.contains(&algorithm) {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    Ok(value)
}
fn structure(
    protected: &[u8],
    aad: &[u8],
    payload: &[u8],
) -> Result<reallyme_cose_proto::SecretBytes, CoseError> {
    let values = [
        ValueRef::Text("MAC"),
        ValueRef::Bytes(protected),
        ValueRef::Bytes(aad),
        ValueRef::Bytes(payload),
    ];
    let value = ValueRef::Array(&values);
    bounded::encode(&value)
}

pub(crate) fn create(
    request: &contract::CoseMacCreateRequest,
) -> Result<contract::CoseMessageCreateResult, CoseError> {
    read_message::aad(&request.external_aad)?;
    let input = request
        .headers
        .as_option()
        .ok_or(CoseError::InvalidFormat)?;
    let headers = read_headers::read(&input.protected, &input.unprotected)?;
    let algorithm = authorize(
        request.algorithm,
        &request.allowed_algorithms,
        headers.algorithm,
    )?;
    let content = read_message::content(&request.payload, request.content_mode)?;
    recipient::allowlist(&request.allowed_recipient_algorithms)?;
    create_recipients::validate(
        &request.recipients,
        &request.allowed_recipient_algorithms,
        algorithm.key_length(),
        1,
        &mut 0,
    )?;
    let structure = structure(headers.protected, &request.external_aad, &request.payload)?;
    let key = create_recipients::key(
        &request.recipients,
        &request.allowed_recipient_algorithms,
        algorithm.key_length(),
    )?;
    let recipients = create_recipients::create(
        &request.recipients,
        &request.allowed_recipient_algorithms,
        &key,
    )?;
    let key = CoseMacKey::new(algorithm, key.into_zeroizing())?;
    let tag = key.authenticate(&structure)?;
    let recipients = bounded::frame(&recipients)?;
    let values = [
        ValueRef::Bytes(headers.protected),
        ValueRef::Received(&headers.unprotected),
        content,
        ValueRef::Bytes(&tag),
        ValueRef::Received(&recipients),
    ];
    let body = ValueRef::Array(&values);
    let value = if request.tagged {
        ValueRef::Tag(97, &body)
    } else {
        ValueRef::Array(&values)
    };
    Ok(contract::CoseMessageCreateResult {
        encoded: bounded::encode(&value)?,
    })
}

pub(crate) fn verify(
    request: &contract::CoseMacVerifyRequest,
) -> Result<contract::CoseMacVerifyResult, CoseError> {
    read_message::aad(&request.external_aad)?;
    let fields = read_message::envelope(&request.encoded, 97, request.envelope, 5)?;
    let [protected, unprotected, content, tag, recipients] = fields.as_slice() else {
        return Err(CoseError::InvalidFormat);
    };
    let headers = read_headers::from_slots(protected, unprotected)?;
    let payload = read_message::payload(content, request.detached_payload.as_deref())?;
    let algorithm = authorize(
        request.algorithm,
        &request.allowed_algorithms,
        headers.algorithm,
    )?;
    let tag = tag.as_bytes().map_err(crate::cbor_boundary::error)?;
    if tag.len() != algorithm.tag_length() {
        return Err(CoseErrorReason::CommonInvalidLength.into());
    }
    recipient::allowlist(&request.allowed_recipient_algorithms)?;
    if request.recipient_path.is_empty()
        || request.recipient_path.len() > recipient::MAX_RECIPIENT_DEPTH
    {
        return Err(CoseError::InvalidRecipient);
    }
    recipient::validate_tree(recipients, 1, &mut 0)?;
    let key = open_recipient::open(
        recipients,
        &request.recipient_path,
        &request.recipient_key,
        &request.allowed_recipient_algorithms,
        algorithm.key_length(),
    )?;
    let key = CoseMacKey::new(algorithm, key.into_zeroizing())?;
    let structure = structure(headers.protected, &request.external_aad, payload)?;
    key.verify(&structure, tag)?;
    Ok(contract::CoseMacVerifyResult {
        algorithm: request.algorithm,
        protected: bounded::copy(headers.protected)?,
        protected_kid: headers.protected_kid.map(bounded::copy).transpose()?,
        attached_payload: request
            .detached_payload
            .is_none()
            .then(|| bounded::copy(payload))
            .transpose()?,
    })
}

pub(crate) fn valid_created(result: &contract::CoseMessageCreateResult) -> bool {
    !result.encoded.is_empty() && result.encoded.len() <= bounded::MAX_MESSAGE_BYTES
}
pub(crate) fn valid_verified(result: &contract::CoseMacVerifyResult) -> bool {
    CoseMacAlgorithm::try_from(result.algorithm).is_ok()
        && result.protected.len() <= read_message::MAX_HEADER_BYTES
        && result
            .attached_payload
            .as_ref()
            .is_none_or(|v| v.len() <= bounded::MAX_MESSAGE_BYTES)
}
