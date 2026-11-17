// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

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

#[cfg(test)]
#[path = "verify_request_result_routing_tests.rs"]
mod routing_tests;

pub(crate) fn from_result(result: CoseWireResult<CoseOperationResult>) -> CoseOperationResponseV2 {
    let outcome = match result {
        Ok(result) => CoseOperationOutcomeV2::Result(Box::new(result)),
        Err(error) => CoseOperationOutcomeV2::Error(Box::new(cose_error(error))),
    };
    CoseOperationResponseV2 {
        outcome: Some(outcome),
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
            CoseErrorReason::BackendResourceLimitExceeded,
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
            CoseErrorReason::BackendResourceLimitExceeded,
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
        Some(CoseOperationResultBranch::KeySetParse(result)) => {
            crate::messages::key_set::valid_parsed_result(result)
        }
        Some(CoseOperationResultBranch::KeySetCreate(result)) => {
            crate::messages::key_set::valid_created_result(result)
        }
        Some(
            CoseOperationResultBranch::Sign1Create(_)
            | CoseOperationResultBranch::Sign1CreateDetached(_)
            | CoseOperationResultBranch::Sign1CreateProfile(_)
            | CoseOperationResultBranch::Sign1CreateDetachedProfile(_)
            | CoseOperationResultBranch::KeyToMultikey(_)
            | CoseOperationResultBranch::MlKemEncryptDirect(_)
            | CoseOperationResultBranch::MlKemEncryptKeyWrap(_),
        ) => true,
        Some(
            CoseOperationResultBranch::KeyFromPublicBytes(message)
            | CoseOperationResultBranch::KeyFromPrivateBytes(message)
            | CoseOperationResultBranch::KeyParse(message)
            | CoseOperationResultBranch::KeyToPublicBytes(message)
            | CoseOperationResultBranch::KeyToPublicVec(message)
            | CoseOperationResultBranch::KeyToPrivateBytes(message)
            | CoseOperationResultBranch::KeyDerivePublicKid(message)
            | CoseOperationResultBranch::MultikeyToCoseKey(message),
        ) => {
            if message.signature_algorithm != CoseSignatureAlgorithm::Unspecified {
                message
                    .signature_algorithm
                    .as_known()
                    .is_some_and(exact_signature_algorithm_is_valid)
            } else {
                message.signature_algorithm.to_i32() == 0
            }
        }
        Some(
            CoseOperationResultBranch::Sign1Verify(message)
            | CoseOperationResultBranch::Sign1VerifyDetached(message)
            | CoseOperationResultBranch::Sign1VerifyProfile(message),
        ) => sign1_metadata_is_valid(message),
        Some(CoseOperationResultBranch::MlKemDecrypt(message)) => {
            decrypt_metadata_is_valid(message)
        }
        Some(
            CoseOperationResultBranch::AgreementKeyCreate(value)
            | CoseOperationResultBranch::AgreementKeyParse(value),
        ) => super::profile_response::agreement(value),
        Some(CoseOperationResultBranch::ContractInfo(value)) => {
            value.constants.len() == crate::generated_contract::CONSTANTS.len()
                && value
                    .constants
                    .iter()
                    .zip(crate::generated_contract::CONSTANTS)
                    .all(|(entry, (constant, number))| {
                        entry.constant == *constant && entry.value == *number
                    })
        }
        Some(CoseOperationResultBranch::Mac0VerifyDetached(value)) => {
            super::profile_response::mac0(value)
        }
        Some(CoseOperationResultBranch::IsoSign1Verify(value)) => {
            super::profile_response::iso(value)
        }
        Some(CoseOperationResultBranch::ContainerVerify(value)) => {
            super::profile_response::container(value)
        }
        Some(CoseOperationResultBranch::PeerKeyInspect(value)) => {
            !value.validated && super::profile_response::peer(value)
        }
        Some(CoseOperationResultBranch::PeerKeyValidate(value)) => {
            value.validated && super::profile_response::peer(value)
        }
        Some(CoseOperationResultBranch::VerificationKeyImport(value)) => {
            super::profile_response::working_key(value)
        }
        Some(CoseOperationResultBranch::SignatureSuiteInfo(value)) => {
            super::profile_response::suite_info(value)
        }
        Some(
            CoseOperationResultBranch::ContainerSign(value)
            | CoseOperationResultBranch::SignatureToCose(value)
            | CoseOperationResultBranch::SignatureToDer(value),
        ) => {
            !value.encoded.is_empty() && value.encoded.len() <= crate::limits::MAX_COSE_SIGN1_BYTES
        }
        Some(
            CoseOperationResultBranch::SignatureValidate(_)
            | CoseOperationResultBranch::PreferredCborValidate(_),
        ) => true,
        Some(CoseOperationResultBranch::Sign1SignatureStructure(value)) => {
            !value.signature_structure.is_empty()
                && value.signature_structure.len() <= MAX_COSE_PROTO_MESSAGE_BYTES
        }
        Some(CoseOperationResultBranch::Sign1VerifyX5chain(value)) => {
            value
                .verified
                .as_option()
                .is_some_and(sign1_metadata_is_valid)
                && value
                    .x5chain
                    .as_option()
                    .is_some_and(|chain| !chain.certificates_der.is_empty())
                && matches!(
                    value.placement.as_known(),
                    Some(
                        crate::wire::CoseX5ChainHeaderPlacement::Protected
                            | crate::wire::CoseX5ChainHeaderPlacement::Unprotected
                    )
                )
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
            Some(cose_operation_request::Operation::Sign1CreateProfile(_)),
            Some(CoseOperationResultBranch::Sign1CreateProfile(_))
        ) | (
            Some(cose_operation_request::Operation::Sign1CreateDetachedProfile(_)),
            Some(CoseOperationResultBranch::Sign1CreateDetachedProfile(_))
        ) | (
            Some(cose_operation_request::Operation::Sign1VerifyProfile(_)),
            Some(CoseOperationResultBranch::Sign1VerifyProfile(_))
        ) | (
            Some(cose_operation_request::Operation::Sign1VerifyX5chain(_)),
            Some(CoseOperationResultBranch::Sign1VerifyX5chain(_))
        ) | (
            Some(cose_operation_request::Operation::AgreementKeyCreate(_)),
            Some(CoseOperationResultBranch::AgreementKeyCreate(_))
        ) | (
            Some(cose_operation_request::Operation::AgreementKeyParse(_)),
            Some(CoseOperationResultBranch::AgreementKeyParse(_))
        ) | (
            Some(cose_operation_request::Operation::Mac0VerifyDetached(_)),
            Some(CoseOperationResultBranch::Mac0VerifyDetached(_))
        ) | (
            Some(cose_operation_request::Operation::IsoSign1Verify(_)),
            Some(CoseOperationResultBranch::IsoSign1Verify(_))
        ) | (
            Some(cose_operation_request::Operation::ContainerVerify(_)),
            Some(CoseOperationResultBranch::ContainerVerify(_))
        ) | (
            Some(cose_operation_request::Operation::ContainerSign(_)),
            Some(CoseOperationResultBranch::ContainerSign(_))
        ) | (
            Some(cose_operation_request::Operation::PeerKeyInspect(_)),
            Some(CoseOperationResultBranch::PeerKeyInspect(_))
        ) | (
            Some(cose_operation_request::Operation::PeerKeyValidate(_)),
            Some(CoseOperationResultBranch::PeerKeyValidate(_))
        ) | (
            Some(cose_operation_request::Operation::SignatureToCose(_)),
            Some(CoseOperationResultBranch::SignatureToCose(_))
        ) | (
            Some(cose_operation_request::Operation::SignatureToDer(_)),
            Some(CoseOperationResultBranch::SignatureToDer(_))
        ) | (
            Some(cose_operation_request::Operation::SignatureValidate(_)),
            Some(CoseOperationResultBranch::SignatureValidate(_))
        ) | (
            Some(cose_operation_request::Operation::SignatureSuiteInfo(_)),
            Some(CoseOperationResultBranch::SignatureSuiteInfo(_))
        ) | (
            Some(cose_operation_request::Operation::VerificationKeyImport(_)),
            Some(CoseOperationResultBranch::VerificationKeyImport(_))
        ) | (
            Some(cose_operation_request::Operation::ContractInfo(_)),
            Some(CoseOperationResultBranch::ContractInfo(_))
        ) | (
            Some(cose_operation_request::Operation::PreferredCborValidate(_)),
            Some(CoseOperationResultBranch::PreferredCborValidate(_))
        ) | (
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
            Some(cose_operation_request::Operation::Sign1SignatureStructure(
                _
            )),
            Some(CoseOperationResultBranch::Sign1SignatureStructure(_)),
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
            Some(cose_operation_request::Operation::KeyToPublicVec(_)),
            Some(CoseOperationResultBranch::KeyToPublicVec(_)),
        ) | (
            Some(cose_operation_request::Operation::KeySetParse(_)),
            Some(CoseOperationResultBranch::KeySetParse(_)),
        ) | (
            Some(cose_operation_request::Operation::KeySetCreate(_)),
            Some(CoseOperationResultBranch::KeySetCreate(_)),
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

// Published legacy selectors remain valid metadata for older callers.
#[allow(deprecated)]
fn signature_algorithm_is_valid(value: EnumValue<CoseSignatureAlgorithm>) -> bool {
    matches!(
        value.as_known(),
        Some(
            CoseSignatureAlgorithm::Ed25519
                | CoseSignatureAlgorithm::EcdsaP256Sha256
                | CoseSignatureAlgorithm::Es256
                | CoseSignatureAlgorithm::Esp256
                | CoseSignatureAlgorithm::EcdsaP384Sha384
                | CoseSignatureAlgorithm::Esp384
                | CoseSignatureAlgorithm::EcdsaP521Sha512
                | CoseSignatureAlgorithm::Esp512
                | CoseSignatureAlgorithm::EcdsaSecp256k1Sha256
                | CoseSignatureAlgorithm::MlDsa44
                | CoseSignatureAlgorithm::MlDsa65
                | CoseSignatureAlgorithm::MlDsa87
        )
    )
}

fn sign1_metadata_is_valid(result: &crate::wire::CoseSign1VerifyResult) -> bool {
    if let Some(cose_type) = result.protected_type.as_option() {
        match cose_type.value.as_ref() {
            Some(crate::wire::cose_type::Value::MediaType(text))
                if !text.is_empty() && text.len() <= crate::MAX_COSE_TYPE_TEXT_BYTES => {}
            Some(crate::wire::cose_type::Value::ContentFormat(_)) => {}
            _ => return false,
        }
    }
    if !signature_algorithm_is_valid(result.algorithm) {
        return false;
    }
    let Some(compatibility) = result.algorithm.as_known() else {
        return false;
    };
    if result.exact_signature_algorithm == CoseSignatureAlgorithm::Unspecified {
        return result.exact_signature_algorithm.to_i32() == 0;
    }
    let Some(exact) = result.exact_signature_algorithm.as_known() else {
        return false;
    };
    signature_algorithm_is_valid(result.algorithm)
        && exact_signature_algorithm_is_valid(exact)
        && signature_algorithms_share_primitive(compatibility, exact)
}

const fn exact_signature_algorithm_is_valid(algorithm: CoseSignatureAlgorithm) -> bool {
    matches!(
        algorithm,
        CoseSignatureAlgorithm::Ed25519
            | CoseSignatureAlgorithm::Es256
            | CoseSignatureAlgorithm::Esp256
            | CoseSignatureAlgorithm::Esp384
            | CoseSignatureAlgorithm::Esp512
            | CoseSignatureAlgorithm::EcdsaSecp256k1Sha256
            | CoseSignatureAlgorithm::MlDsa44
            | CoseSignatureAlgorithm::MlDsa65
            | CoseSignatureAlgorithm::MlDsa87
    )
}

// Published legacy selectors remain valid metadata for older callers.
#[allow(deprecated)]
const fn signature_algorithms_share_primitive(
    compatibility: CoseSignatureAlgorithm,
    exact: CoseSignatureAlgorithm,
) -> bool {
    matches!(
        (compatibility, exact),
        (
            CoseSignatureAlgorithm::Ed25519,
            CoseSignatureAlgorithm::Ed25519,
        ) | (
            CoseSignatureAlgorithm::EcdsaP256Sha256
                | CoseSignatureAlgorithm::Es256
                | CoseSignatureAlgorithm::Esp256,
            CoseSignatureAlgorithm::Es256 | CoseSignatureAlgorithm::Esp256,
        ) | (
            CoseSignatureAlgorithm::EcdsaP384Sha384 | CoseSignatureAlgorithm::Esp384,
            CoseSignatureAlgorithm::Esp384,
        ) | (
            CoseSignatureAlgorithm::EcdsaP521Sha512 | CoseSignatureAlgorithm::Esp512,
            CoseSignatureAlgorithm::Esp512,
        ) | (
            CoseSignatureAlgorithm::EcdsaSecp256k1Sha256,
            CoseSignatureAlgorithm::EcdsaSecp256k1Sha256,
        ) | (
            CoseSignatureAlgorithm::MlDsa44,
            CoseSignatureAlgorithm::MlDsa44,
        ) | (
            CoseSignatureAlgorithm::MlDsa65,
            CoseSignatureAlgorithm::MlDsa65,
        ) | (
            CoseSignatureAlgorithm::MlDsa87,
            CoseSignatureAlgorithm::MlDsa87,
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
    if matches!(
        error.reason(),
        CoseErrorReason::BackendResourceLimitExceeded
    ) {
        CoseWireError::backend_internal(CoseErrorReason::BackendResourceLimitExceeded)
    } else {
        malformed_response_error()
    }
}

const fn malformed_response_error() -> CoseWireError {
    CoseWireError::backend_internal(CoseErrorReason::BackendInternal)
}
