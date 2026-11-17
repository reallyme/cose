// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    bounded, counter_signature, counter_structure, counter_target, read_message, signature_crypto,
};
use crate::api::contract::{
    self as contract, __buffa::oneof::cose_counter_signature0verify_request::Signature,
};
use crate::CoseError;
use reallyme_codec::cbor::general::ValueRef;

pub(crate) fn create(
    request: &contract::CoseCounterSignature0CreateRequest,
) -> Result<contract::CoseMessageCreateResult, CoseError> {
    read_message::aad(&request.external_aad)?;
    let target =
        counter_target::parse(request.target.as_option().ok_or(CoseError::InvalidFormat)?)?;
    let suite = request
        .suite
        .as_option()
        .ok_or(CoseError::InvalidKeyMaterial)?;
    let algorithm = counter_signature::external_algorithm(suite, &request.allowed_suites)?;
    let structure = counter_structure::encode(&target, None, &request.external_aad)?;
    let signature = signature_crypto::sign(algorithm, &request.private_key, &structure)?;
    let value = ValueRef::Bytes(&signature);
    Ok(contract::CoseMessageCreateResult {
        encoded: bounded::encode(&value)?,
    })
}

pub(crate) fn verify(
    request: &contract::CoseCounterSignature0VerifyRequest,
) -> Result<contract::CoseCounterSignatureVerifyResult, CoseError> {
    read_message::aad(&request.external_aad)?;
    let target =
        counter_target::parse(request.target.as_option().ok_or(CoseError::InvalidFormat)?)?;
    let key = request
        .key
        .as_option()
        .ok_or(CoseError::InvalidKeyMaterial)?;
    if key.signature_index != 0 {
        return Err(CoseError::InvalidKeyMaterial);
    }
    let signature = match request.signature.as_ref() {
        Some(Signature::Standalone(encoded)) => bounded::validated(encoded)?
            .frame()
            .as_bytes()
            .map_err(crate::cbor_boundary::error)?,
        Some(Signature::Header(_)) => {
            counter_target::header(&target, counter_target::ABBREVIATED_HEADER)?
                .ok_or(CoseError::InvalidFormat)?
                .as_bytes()
                .map_err(crate::cbor_boundary::error)?
        }
        None => return Err(CoseError::InvalidFormat),
    };
    let suite = key.suite.as_option().ok_or(CoseError::InvalidKeyMaterial)?;
    let algorithm = counter_signature::external_algorithm(suite, &request.allowed_suites)?;
    let structure = counter_structure::encode(&target, None, &request.external_aad)?;
    signature_crypto::verify(algorithm, &key.public_key, &structure, signature)?;
    counter_signature::receipt(suite, &[], None, target.protected)
}
pub(crate) fn valid_created(result: &contract::CoseMessageCreateResult) -> bool {
    counter_signature::valid_created(result)
}
pub(crate) fn valid_verified(result: &contract::CoseCounterSignatureVerifyResult) -> bool {
    counter_signature::valid_verified(result)
        && result.protected.is_empty()
        && result.protected_kid.is_none()
}
