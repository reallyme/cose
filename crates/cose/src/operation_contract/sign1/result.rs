// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Generated-result conversion for COSE_Sign1 operations.

use buffa::EnumValue;
use reallyme_crypto::core::Algorithm;
use zeroize::Zeroizing;

use crate::sign1::sign::CoseSign1CreateOutput;
use crate::sign1::verify::{VerifiedCoseSign1, VerifiedDetachedCoseSign1};
use crate::wire::{
    cose_operation_result::Result as OperationResultBranch, CoseErrorReason, CoseOperationResult,
    CoseSign1CreateResult, CoseSign1VerifyResult, CoseSignatureAlgorithm, CoseWireError,
    CoseWireResult,
};

pub(crate) fn created_attached(output: CoseSign1CreateOutput) -> CoseOperationResult {
    operation_result(OperationResultBranch::Sign1Create(Box::new(
        create_message(output),
    )))
}

pub(crate) fn created_detached(output: CoseSign1CreateOutput) -> CoseOperationResult {
    operation_result(OperationResultBranch::Sign1CreateDetached(Box::new(
        create_message(output),
    )))
}

pub(crate) fn verified_attached(output: VerifiedCoseSign1) -> CoseWireResult<CoseOperationResult> {
    let message = verify_message(output.payload, output.alg, output.kid)?;
    Ok(operation_result(OperationResultBranch::Sign1Verify(
        Box::new(message),
    )))
}

pub(crate) fn verified_detached(
    output: VerifiedDetachedCoseSign1,
) -> CoseWireResult<CoseOperationResult> {
    let message = verify_message(Zeroizing::new(Vec::new()), output.alg, output.kid)?;
    Ok(operation_result(
        OperationResultBranch::Sign1VerifyDetached(Box::new(message)),
    ))
}

fn create_message(output: CoseSign1CreateOutput) -> CoseSign1CreateResult {
    let mut cose_sign1 = output.into_zeroizing();
    CoseSign1CreateResult {
        cose_sign1: core::mem::take(&mut *cose_sign1),
        __buffa_unknown_fields: Default::default(),
    }
}

fn verify_message(
    mut payload: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    mut kid: Zeroizing<Vec<u8>>,
) -> CoseWireResult<CoseSign1VerifyResult> {
    Ok(CoseSign1VerifyResult {
        payload: core::mem::take(&mut *payload),
        algorithm: EnumValue::from(signature_algorithm_to_proto(algorithm)?),
        kid: core::mem::take(&mut *kid),
        __buffa_unknown_fields: Default::default(),
    })
}

fn operation_result(result: OperationResultBranch) -> CoseOperationResult {
    CoseOperationResult {
        result: Some(result),
        __buffa_unknown_fields: Default::default(),
    }
}

fn signature_algorithm_to_proto(algorithm: Algorithm) -> CoseWireResult<CoseSignatureAlgorithm> {
    match algorithm {
        Algorithm::Ed25519 => Ok(CoseSignatureAlgorithm::Ed25519),
        Algorithm::P256 => Ok(CoseSignatureAlgorithm::EcdsaP256Sha256),
        Algorithm::P384 => Ok(CoseSignatureAlgorithm::EcdsaP384Sha384),
        Algorithm::P521 => Ok(CoseSignatureAlgorithm::EcdsaP521Sha512),
        Algorithm::Secp256k1 => Ok(CoseSignatureAlgorithm::EcdsaSecp256k1Sha256),
        Algorithm::MlDsa44 => Ok(CoseSignatureAlgorithm::MlDsa44),
        Algorithm::MlDsa65 => Ok(CoseSignatureAlgorithm::MlDsa65),
        Algorithm::MlDsa87 => Ok(CoseSignatureAlgorithm::MlDsa87),
        Algorithm::X25519
        | Algorithm::MlKem512
        | Algorithm::MlKem768
        | Algorithm::MlKem1024
        | Algorithm::SlhDsaSha2_128s
        | Algorithm::XWing768 => Err(CoseWireError::provider_internal(
            CoseErrorReason::CommonUnsupportedAlgorithm,
        )),
    }
}
