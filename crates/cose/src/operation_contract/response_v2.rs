// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Generated operation-response construction and validation.

use buffa::EnumValue;
use zeroize::Zeroizing;

use crate::wire::{
    cose_error, cose_operation_request, decode_protobuf_with_limit, encode_protobuf,
    validate_cose_error_proto_wire, CoseContentEncryptionAlgorithm, CoseErrorReason,
    CoseKemAlgorithm, CoseMlKemDecryptResult, CoseMlKemMode, CoseOperationOutcomeV2,
    CoseOperationRequest, CoseOperationResponseV2, CoseOperationResult, CoseOperationResultBranch,
    CoseSignatureAlgorithm, CoseWireError, CoseWireResult, MAX_COSE_PROTO_MESSAGE_BYTES,
};

const MAX_RESPONSE_OVERHEAD_BYTES: usize = 32;

pub(crate) fn from_result(result: CoseWireResult<CoseOperationResult>) -> CoseOperationResponseV2 {
    let outcome = match result {
        Ok(result) => CoseOperationOutcomeV2::Result(Box::new(result)),
        Err(error) => CoseOperationOutcomeV2::Error(Box::new(cose_error(error))),
    };
    CoseOperationResponseV2 {
        outcome: Some(outcome),
        __buffa_unknown_fields: Default::default(),
    }
}

pub(crate) fn from_error(error: CoseWireError) -> CoseOperationResponseV2 {
    from_result(Err(error))
}

pub(crate) fn encode_or_error(response: &CoseOperationResponseV2) -> Zeroizing<Vec<u8>> {
    let encoded = encode_protobuf(response);
    let maximum = match maximum_response_bytes() {
        Ok(maximum) => maximum,
        Err(error) => return encode_protobuf(&from_result(Err(error))),
    };
    if encoded.len() > maximum {
        return encode_protobuf(&from_result(Err(CoseWireError::backend_internal(
            CoseErrorReason::CommonResourceLimitExceeded,
        ))));
    }
    encoded
}

pub(crate) fn decode_for_request(
    request: &CoseOperationRequest,
    bytes: &[u8],
) -> Result<CoseOperationResponseV2, CoseOperationResponseV2> {
    let response = decode(bytes)?;
    validate_for_request(request, &response).map_err(from_error)?;
    Ok(response)
}

pub(crate) fn decode(bytes: &[u8]) -> Result<CoseOperationResponseV2, CoseOperationResponseV2> {
    let maximum = maximum_response_bytes().map_err(from_error)?;
    if bytes.len() > maximum {
        return Err(from_result(Err(CoseWireError::backend_internal(
            CoseErrorReason::CommonResourceLimitExceeded,
        ))));
    }

    let response = decode_protobuf_with_limit::<CoseOperationResponseV2>(bytes, maximum)
        .map_err(|error| from_result(Err(response_boundary_error(error))))?;
    validate(&response).map_err(from_error)?;
    Ok(response)
}

fn validate(response: &CoseOperationResponseV2) -> CoseWireResult<()> {
    match response.outcome.as_ref() {
        Some(CoseOperationOutcomeV2::Result(result)) => validate_result(result),
        Some(CoseOperationOutcomeV2::Error(error)) => {
            validate_cose_error_proto_wire(error).map_err(|_| malformed_response_error())
        }
        None => Err(malformed_response_error()),
    }
}

fn validate_for_request(
    request: &CoseOperationRequest,
    response: &CoseOperationResponseV2,
) -> CoseWireResult<()> {
    match response.outcome.as_ref() {
        Some(CoseOperationOutcomeV2::Result(result)) => {
            if result_matches_request(request, result) {
                Ok(())
            } else {
                Err(malformed_response_error())
            }
        }
        Some(CoseOperationOutcomeV2::Error(_)) => Ok(()),
        None => Err(malformed_response_error()),
    }
}

fn validate_result(result: &CoseOperationResult) -> CoseWireResult<()> {
    let valid = match result.result.as_ref() {
        Some(
            CoseOperationResultBranch::Sign1Create(_)
            | CoseOperationResultBranch::Sign1CreateDetached(_)
            | CoseOperationResultBranch::KeyFromPublicBytes(_)
            | CoseOperationResultBranch::KeyFromPrivateBytes(_)
            | CoseOperationResultBranch::KeyParse(_)
            | CoseOperationResultBranch::KeyToPublicBytes(_)
            | CoseOperationResultBranch::KeyToPrivateBytes(_)
            | CoseOperationResultBranch::KeyDerivePublicKid(_)
            | CoseOperationResultBranch::KeyToMultikey(_)
            | CoseOperationResultBranch::MultikeyToCoseKey(_)
            | CoseOperationResultBranch::MlKemEncryptDirect(_)
            | CoseOperationResultBranch::MlKemEncryptKeyWrap(_),
        ) => true,
        Some(
            CoseOperationResultBranch::Sign1Verify(message)
            | CoseOperationResultBranch::Sign1VerifyDetached(message),
        ) => signature_algorithm_is_valid(message.algorithm),
        Some(CoseOperationResultBranch::MlKemDecrypt(message)) => {
            decrypt_metadata_is_valid(message)
        }
        None => false,
    };
    if valid {
        Ok(())
    } else {
        Err(malformed_response_error())
    }
}

fn result_matches_request(request: &CoseOperationRequest, result: &CoseOperationResult) -> bool {
    matches!(
        (request.operation.as_ref(), result.result.as_ref()),
        (
            Some(cose_operation_request::Operation::Sign1Create(_)),
            Some(CoseOperationResultBranch::Sign1Create(_)),
        ) | (
            Some(cose_operation_request::Operation::Sign1CreateDetached(_)),
            Some(CoseOperationResultBranch::Sign1CreateDetached(_)),
        ) | (
            Some(cose_operation_request::Operation::Sign1Verify(_)),
            Some(CoseOperationResultBranch::Sign1Verify(_)),
        ) | (
            Some(cose_operation_request::Operation::Sign1VerifyDetached(_)),
            Some(CoseOperationResultBranch::Sign1VerifyDetached(_)),
        ) | (
            Some(cose_operation_request::Operation::KeyFromPublicBytes(_)),
            Some(CoseOperationResultBranch::KeyFromPublicBytes(_)),
        ) | (
            Some(cose_operation_request::Operation::KeyFromPrivateBytes(_)),
            Some(CoseOperationResultBranch::KeyFromPrivateBytes(_)),
        ) | (
            Some(cose_operation_request::Operation::KeyParse(_)),
            Some(CoseOperationResultBranch::KeyParse(_)),
        ) | (
            Some(cose_operation_request::Operation::KeyToPublicBytes(_)),
            Some(CoseOperationResultBranch::KeyToPublicBytes(_)),
        ) | (
            Some(cose_operation_request::Operation::KeyToPrivateBytes(_)),
            Some(CoseOperationResultBranch::KeyToPrivateBytes(_)),
        ) | (
            Some(cose_operation_request::Operation::KeyDerivePublicKid(_)),
            Some(CoseOperationResultBranch::KeyDerivePublicKid(_)),
        ) | (
            Some(cose_operation_request::Operation::KeyToMultikey(_)),
            Some(CoseOperationResultBranch::KeyToMultikey(_)),
        ) | (
            Some(cose_operation_request::Operation::MultikeyToCoseKey(_)),
            Some(CoseOperationResultBranch::MultikeyToCoseKey(_)),
        ) | (
            Some(cose_operation_request::Operation::MlKemEncryptDirect(_)),
            Some(CoseOperationResultBranch::MlKemEncryptDirect(_)),
        ) | (
            Some(cose_operation_request::Operation::MlKemEncryptKeyWrap(_)),
            Some(CoseOperationResultBranch::MlKemEncryptKeyWrap(_)),
        ) | (
            Some(cose_operation_request::Operation::MlKemDecrypt(_)),
            Some(CoseOperationResultBranch::MlKemDecrypt(_)),
        )
    )
}

fn signature_algorithm_is_valid(value: EnumValue<CoseSignatureAlgorithm>) -> bool {
    matches!(
        value.as_known(),
        Some(
            CoseSignatureAlgorithm::Ed25519
                | CoseSignatureAlgorithm::EcdsaP256Sha256
                | CoseSignatureAlgorithm::EcdsaP384Sha384
                | CoseSignatureAlgorithm::EcdsaP521Sha512
                | CoseSignatureAlgorithm::EcdsaSecp256k1Sha256
                | CoseSignatureAlgorithm::MlDsa44
                | CoseSignatureAlgorithm::MlDsa65
                | CoseSignatureAlgorithm::MlDsa87
        )
    )
}

fn decrypt_metadata_is_valid(result: &CoseMlKemDecryptResult) -> bool {
    matches!(
        result.content_algorithm.as_known(),
        Some(
            CoseContentEncryptionAlgorithm::Aes128Gcm
                | CoseContentEncryptionAlgorithm::Aes192Gcm
                | CoseContentEncryptionAlgorithm::Aes256Gcm
        )
    ) && matches!(
        result.kem_algorithm.as_known(),
        Some(CoseKemAlgorithm::MlKem512 | CoseKemAlgorithm::MlKem768 | CoseKemAlgorithm::MlKem1024)
    ) && matches!(
        result.mode.as_known(),
        Some(CoseMlKemMode::Direct | CoseMlKemMode::KeyWrap)
    )
}

fn maximum_response_bytes() -> CoseWireResult<usize> {
    MAX_COSE_PROTO_MESSAGE_BYTES
        .checked_add(MAX_RESPONSE_OVERHEAD_BYTES)
        .ok_or(CoseWireError::backend_internal(
            CoseErrorReason::BackendInternal,
        ))
}

const fn response_boundary_error(error: CoseWireError) -> CoseWireError {
    if matches!(error.reason(), CoseErrorReason::CommonResourceLimitExceeded) {
        CoseWireError::backend_internal(CoseErrorReason::CommonResourceLimitExceeded)
    } else {
        malformed_response_error()
    }
}

const fn malformed_response_error() -> CoseWireError {
    CoseWireError::backend_internal(CoseErrorReason::BackendInternal)
}
