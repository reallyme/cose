// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{bounded, read_headers, read_message, signature_crypto};
use crate::api::contract::{self as contract};
use crate::{cbor_boundary, CoseError};
use reallyme_codec::cbor::general::{MajorType, ValueRef};

pub(super) fn structure(
    body: &[u8],
    signer: &[u8],
    aad: &[u8],
    payload: &[u8],
) -> Result<reallyme_cose_proto::SecretBytes, CoseError> {
    let values = [
        ValueRef::Text("Signature"),
        ValueRef::Bytes(body),
        ValueRef::Bytes(signer),
        ValueRef::Bytes(aad),
        ValueRef::Bytes(payload),
    ];
    let value = ValueRef::Array(&values);
    bounded::encode(&value)
}

fn effective_algorithm(
    body: &read_headers::Headers<'_>,
    signer: &read_headers::Headers<'_>,
) -> Result<i64, CoseError> {
    match (body.algorithm, signer.algorithm) {
        (Some(value), None) | (None, Some(value)) => Ok(value),
        (Some(_), Some(_)) => Err(CoseError::DuplicateMapLabel),
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

pub(crate) fn create(
    request: &contract::CoseSignCreateRequest,
) -> Result<contract::CoseMessageCreateResult, CoseError> {
    read_message::aad(&request.external_aad)?;
    let input = request
        .headers
        .as_option()
        .ok_or(CoseError::InvalidFormat)?;
    let body = read_headers::read(&input.protected, &input.unprotected)?;
    if request.signers.is_empty() || request.signers.len() > read_message::MAX_SIGNATURES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let content = read_message::content(&request.payload, request.content_mode)?;
    let mut signatures = Vec::new();
    signatures
        .try_reserve_exact(request.signers.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for signer in &request.signers {
        let input = signer.headers.as_option().ok_or(CoseError::InvalidFormat)?;
        let headers = read_headers::read(&input.protected, &input.unprotected)?;
        let suite = signer
            .suite
            .as_option()
            .ok_or(CoseError::UnsupportedAlgorithm)?;
        let algorithm = signature_crypto::authorize(
            suite,
            &request.allowed_suites,
            effective_algorithm(&body, &headers)?,
        )?;
        let structure = structure(
            body.protected,
            headers.protected,
            &request.external_aad,
            &request.payload,
        )?;
        let signature = signature_crypto::sign(algorithm, &signer.private_key, &structure)?;
        let values = [
            ValueRef::Bytes(headers.protected),
            ValueRef::Received(&headers.unprotected),
            ValueRef::Bytes(&signature),
        ];
        let value = ValueRef::Array(&values);
        signatures.push(bounded::encode(&value)?);
    }
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(signatures.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for signature in &signatures {
        frames.push(bounded::frame(signature)?);
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(frames.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for frame in &frames {
        values.push(ValueRef::Received(frame));
    }
    let fields = [
        ValueRef::Bytes(body.protected),
        ValueRef::Received(&body.unprotected),
        content,
        ValueRef::Array(&values),
    ];
    let body = ValueRef::Array(&fields);
    let value = if request.tagged {
        ValueRef::Tag(read_message::COSE_SIGN_TAG, &body)
    } else {
        ValueRef::Array(&fields)
    };
    Ok(contract::CoseMessageCreateResult {
        encoded: bounded::encode(&value)?,
    })
}

pub(crate) fn verify(
    request: &contract::CoseSignVerifyRequest,
) -> Result<contract::CoseSignVerifyResult, CoseError> {
    read_message::aad(&request.external_aad)?;
    let fields = read_message::envelope(
        &request.encoded,
        read_message::COSE_SIGN_TAG,
        request.envelope,
        4,
    )?;
    let [protected, unprotected, content, signatures] = fields.as_slice() else {
        return Err(CoseError::InvalidFormat);
    };
    let body = read_headers::from_slots(protected, unprotected)?;
    let payload = read_message::payload(content, request.detached_payload.as_deref())?;
    let signatures =
        read_message::children(signatures, MajorType::Array, read_message::MAX_SIGNATURES)?;
    if signatures.is_empty() || request.keys.len() != signatures.len() {
        return Err(CoseError::InvalidKeyMaterial);
    }
    let mut verified = Vec::new();
    verified
        .try_reserve_exact(signatures.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for (index, signature) in signatures.iter().enumerate() {
        let parts = read_message::children(signature, MajorType::Array, 3)?;
        let [protected, unprotected, signature] = parts.as_slice() else {
            return Err(CoseError::InvalidFormat);
        };
        let headers = read_headers::from_slots(protected, unprotected)?;
        let key = request
            .keys
            .get(index)
            .ok_or(CoseError::InvalidKeyMaterial)?;
        if usize::try_from(key.signature_index).ok() != Some(index) {
            return Err(CoseError::InvalidKeyMaterial);
        }
        let suite = key.suite.as_option().ok_or(CoseError::InvalidKeyMaterial)?;
        let algorithm = signature_crypto::authorize(
            suite,
            &request.allowed_suites,
            effective_algorithm(&body, &headers)?,
        )?;
        let structure = structure(
            body.protected,
            headers.protected,
            &request.external_aad,
            payload,
        )?;
        signature_crypto::verify(
            algorithm,
            &key.public_key,
            &structure,
            signature.as_bytes().map_err(cbor_boundary::error)?,
        )?;
        verified.push(contract::CoseVerifiedSignature {
            signature_index: key.signature_index,
            suite: buffa::MessageField::some(suite.clone()),
            protected: bounded::copy(headers.protected)?,
            protected_kid: headers.protected_kid.map(bounded::copy).transpose()?,
        });
    }
    Ok(contract::CoseSignVerifyResult {
        body_protected: bounded::copy(body.protected)?,
        attached_payload: request
            .detached_payload
            .is_none()
            .then(|| bounded::copy(payload))
            .transpose()?,
        signatures: verified.into(),
    })
}

pub(crate) fn valid_result(result: &contract::CoseSignVerifyResult) -> bool {
    !result.signatures.is_empty()
        && result.signatures.len() <= read_message::MAX_SIGNATURES
        && result.body_protected.len() <= read_message::MAX_HEADER_BYTES
        && result
            .attached_payload
            .as_ref()
            .is_none_or(|v| v.len() <= bounded::MAX_MESSAGE_BYTES)
        && result.signatures.iter().enumerate().all(|(index, value)| {
            usize::try_from(value.signature_index).ok() == Some(index)
                && value
                    .suite
                    .as_option()
                    .is_some_and(|suite| signature_crypto::algorithm(suite).is_ok())
                && value.protected.len() <= read_message::MAX_HEADER_BYTES
        })
}
