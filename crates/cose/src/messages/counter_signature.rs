// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    bounded, counter_structure, counter_target, read_headers, read_message, signature_crypto,
};
use crate::api::contract::{
    self as contract, __buffa::oneof::cose_counter_signature_verify_request::Signature,
};
use crate::{CoseError, CoseSignatureAlgorithm};
use reallyme_codec::cbor::general::{Frame, MajorType, ValueRef};

pub(super) fn full<'a>(
    encoded: &'a [u8],
    envelope: buffa::EnumValue<contract::CoseEnvelopePolicy>,
) -> Result<Vec<Frame<'a>>, CoseError> {
    let fields = read_message::envelope(encoded, counter_target::COUNTER_TAG, envelope, 3)?;
    let [protected, unprotected, signature] = fields.as_slice() else {
        return Err(CoseError::InvalidFormat);
    };
    let headers = read_headers::from_slots(protected, unprotected)?;
    if headers.algorithm.is_none() {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    if signature
        .as_bytes()
        .map_err(crate::cbor_boundary::error)?
        .is_empty()
    {
        return Err(CoseError::InvalidSignatureEncoding);
    }
    Ok(fields)
}

fn collection_member(frame: &Frame<'_>) -> Result<(), CoseError> {
    let parts = read_message::children(frame, MajorType::Array, 3)?;
    let [protected, unprotected, signature] = parts.as_slice() else {
        return Err(CoseError::InvalidFormat);
    };
    counter_target::headers(
        protected.as_bytes().map_err(crate::cbor_boundary::error)?,
        unprotected,
    )?;
    if signature
        .as_bytes()
        .map_err(crate::cbor_boundary::error)?
        .is_empty()
    {
        return Err(CoseError::InvalidSignatureEncoding);
    }
    Ok(())
}

pub(super) fn collection<'a>(header: &Frame<'a>) -> Result<Vec<Frame<'a>>, CoseError> {
    let children = read_message::children(header, MajorType::Array, read_message::MAX_SIGNATURES)?;
    let first = children.first().ok_or(CoseError::InvalidFormat)?;
    if first.header().major_type() == MajorType::Bytes {
        collection_member(header)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(1)
            .map_err(|_| CoseError::ResourceLimitExceeded)?;
        output.push(bounded::frame(header.received_bytes())?);
        Ok(output)
    } else {
        for child in &children {
            collection_member(child)?;
        }
        Ok(children)
    }
}

pub(crate) fn create(
    request: &contract::CoseCounterSignatureCreateRequest,
) -> Result<contract::CoseMessageCreateResult, CoseError> {
    read_message::aad(&request.external_aad)?;
    let target =
        counter_target::parse(request.target.as_option().ok_or(CoseError::InvalidFormat)?)?;
    let signer = request
        .signer
        .as_option()
        .ok_or(CoseError::InvalidKeyMaterial)?;
    let input = signer.headers.as_option().ok_or(CoseError::InvalidFormat)?;
    let headers = read_headers::read(&input.protected, &input.unprotected)?;
    let suite = signer
        .suite
        .as_option()
        .ok_or(CoseError::InvalidKeyMaterial)?;
    let algorithm = signature_crypto::authorize(
        suite,
        &request.allowed_suites,
        headers.algorithm.ok_or(CoseError::UnsupportedAlgorithm)?,
    )?;
    let structure =
        counter_structure::encode(&target, Some(headers.protected), &request.external_aad)?;
    let signature = signature_crypto::sign(algorithm, &signer.private_key, &structure)?;
    let fields = [
        ValueRef::Bytes(headers.protected),
        ValueRef::Received(&headers.unprotected),
        ValueRef::Bytes(&signature),
    ];
    let body = ValueRef::Array(&fields);
    let value = if request.tagged {
        ValueRef::Tag(counter_target::COUNTER_TAG, &body)
    } else {
        ValueRef::Array(&fields)
    };
    Ok(contract::CoseMessageCreateResult {
        encoded: bounded::encode(&value)?,
    })
}

pub(crate) fn verify(
    request: &contract::CoseCounterSignatureVerifyRequest,
) -> Result<contract::CoseCounterSignatureVerifyResult, CoseError> {
    read_message::aad(&request.external_aad)?;
    let target =
        counter_target::parse(request.target.as_option().ok_or(CoseError::InvalidFormat)?)?;
    let key = request
        .key
        .as_option()
        .ok_or(CoseError::InvalidKeyMaterial)?;
    let parts = match request.signature.as_ref() {
        Some(Signature::Standalone(encoded)) => {
            if key.signature_index != 0 {
                return Err(CoseError::InvalidKeyMaterial);
            }
            full(&encoded.encoded, encoded.envelope)?
        }
        Some(Signature::HeaderIndex(index)) => {
            if key.signature_index != *index {
                return Err(CoseError::InvalidKeyMaterial);
            }
            let header = counter_target::header(&target, counter_target::FULL_HEADER)?
                .ok_or(CoseError::InvalidFormat)?;
            let counters = collection(&header)?;
            let counter = counters
                .get(usize::try_from(*index).map_err(|_| CoseError::InvalidFormat)?)
                .ok_or(CoseError::InvalidFormat)?;
            full(
                counter.received_bytes(),
                contract::CoseEnvelopePolicy::Untagged.into(),
            )?
        }
        None => return Err(CoseError::InvalidFormat),
    };
    let [protected, unprotected, signature] = parts.as_slice() else {
        return Err(CoseError::InvalidFormat);
    };
    let headers = read_headers::from_slots(protected, unprotected)?;
    let suite = key.suite.as_option().ok_or(CoseError::InvalidKeyMaterial)?;
    let algorithm = signature_crypto::authorize(
        suite,
        &request.allowed_suites,
        headers.algorithm.ok_or(CoseError::UnsupportedAlgorithm)?,
    )?;
    let structure =
        counter_structure::encode(&target, Some(headers.protected), &request.external_aad)?;
    signature_crypto::verify(
        algorithm,
        &key.public_key,
        &structure,
        signature.as_bytes().map_err(crate::cbor_boundary::error)?,
    )?;
    receipt(
        suite,
        headers.protected,
        headers.protected_kid,
        target.protected,
    )
}

pub(super) fn receipt(
    suite: &contract::CoseSignatureSuite,
    protected: &[u8],
    kid: Option<&[u8]>,
    target: &[u8],
) -> Result<contract::CoseCounterSignatureVerifyResult, CoseError> {
    Ok(contract::CoseCounterSignatureVerifyResult {
        suite: buffa::MessageField::some(suite.clone()),
        protected: bounded::copy(protected)?,
        protected_kid: kid.map(bounded::copy).transpose()?,
        target_protected: bounded::copy(target)?,
    })
}

pub(crate) fn valid_created(result: &contract::CoseMessageCreateResult) -> bool {
    super::mac::valid_created(result)
}
pub(crate) fn valid_verified(result: &contract::CoseCounterSignatureVerifyResult) -> bool {
    result
        .suite
        .as_option()
        .is_some_and(|suite| signature_crypto::algorithm(suite).is_ok())
        && result.protected.len() <= read_message::MAX_HEADER_BYTES
        && result.target_protected.len() <= read_message::MAX_HEADER_BYTES
}

pub(super) fn external_algorithm(
    suite: &contract::CoseSignatureSuite,
    allowed: &[contract::CoseSignatureSuite],
) -> Result<signature_crypto::Backend, CoseError> {
    signature_crypto::authorize(
        suite,
        allowed,
        CoseSignatureAlgorithm::try_from(suite.registration)?.identifier(),
    )
}
