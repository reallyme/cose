// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{bounded, read_headers, read_message, rsa, signature_crypto};
use crate::api::contract::{self as contract, CoseErrorReason};
use crate::{CoseError, CoseSignatureAlgorithm};

pub(crate) fn verify(
    request: &contract::CoseRsaSign1VerifyRequest,
) -> Result<contract::CoseRsaSign1VerifyResult, CoseError> {
    read_message::aad(&request.external_aad)?;
    if request.allowed_suites.is_empty()
        || request.allowed_suites.len() > signature_crypto::MAX_ALLOWED_SUITES
    {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    let key = request
        .key
        .as_option()
        .ok_or(CoseError::InvalidKeyMaterial)?;
    if key.signature_index != 0 {
        return Err(CoseError::InvalidKeyMaterial);
    }
    let suite = key.suite.as_option().ok_or(CoseError::InvalidKeyMaterial)?;
    if rsa::parameters(CoseSignatureAlgorithm::try_from(suite.registration)?).is_none() {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    // Reject an invalid key suite before operation-policy comparison: a named
    // curve cannot turn an RSA credential into an EC key.
    let _ = signature_crypto::algorithm(suite)?;
    for allowed in &request.allowed_suites {
        if rsa::parameters(CoseSignatureAlgorithm::try_from(allowed.registration)?).is_none() {
            return Err(CoseError::UnsupportedAlgorithm);
        }
    }
    if request
        .expected_kid
        .as_ref()
        .is_some_and(|kid| kid.len() > read_message::MAX_HEADER_BYTES)
    {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let fields = read_message::envelope(
        &request.encoded,
        read_message::COSE_SIGN1_TAG,
        request.envelope,
        4,
    )?;
    let [protected, unprotected, content, signature] = fields.as_slice() else {
        return Err(CoseError::InvalidFormat);
    };
    let headers = read_headers::from_slots(protected, unprotected)?;
    let algorithm = signature_crypto::authorize(
        suite,
        &request.allowed_suites,
        headers.algorithm.ok_or(CoseError::UnsupportedAlgorithm)?,
    )?;
    if let Some(expected) = request.expected_kid.as_deref() {
        if !headers
            .protected_kid
            .is_some_and(|kid| reallyme_crypto::operations::constant_time::equal(expected, kid))
        {
            return Err(CoseErrorReason::Sign1KidKeyMismatch.into());
        }
    }
    let payload = read_message::payload(content, request.detached_payload.as_deref())?;
    let structure = crate::sign1::build_sign1_signature_structure(
        headers.protected,
        &request.external_aad,
        payload,
        bounded::MAX_MESSAGE_BYTES,
    )?;
    signature_crypto::verify(
        algorithm,
        &key.public_key,
        &structure,
        signature.as_bytes().map_err(crate::cbor_boundary::error)?,
    )?;
    Ok(contract::CoseRsaSign1VerifyResult {
        suite: buffa::MessageField::some(suite.clone()),
        protected: bounded::copy(headers.protected)?,
        protected_kid: headers.protected_kid.map(bounded::copy).transpose()?,
        attached_payload: request
            .detached_payload
            .is_none()
            .then(|| bounded::copy(payload))
            .transpose()?,
    })
}

pub(crate) fn valid_result(value: &contract::CoseRsaSign1VerifyResult) -> bool {
    value.suite.as_option().is_some_and(|suite| {
        matches!(
            signature_crypto::algorithm(suite),
            Ok(signature_crypto::Backend::Rsa(_))
        )
    }) && value.protected.len() <= read_message::MAX_HEADER_BYTES
        && read_headers::read(&value.protected, &[0xa0]).is_ok_and(|headers| {
            value.suite.as_option().is_some_and(|suite| {
                CoseSignatureAlgorithm::try_from(suite.registration)
                    .is_ok_and(|registration| headers.algorithm == Some(registration.identifier()))
            }) && headers.protected_kid == value.protected_kid.as_deref()
        })
        && value
            .attached_payload
            .as_ref()
            .is_none_or(|p| p.len() <= bounded::MAX_MESSAGE_BYTES)
}
