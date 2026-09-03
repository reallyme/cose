// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Generated-result conversion for COSE_Sign1 operations.

use buffa::EnumValue;
use zeroize::Zeroizing;

use crate::algorithm::CoseSignatureAlgorithm as NativeCoseSignatureAlgorithm;
use crate::sign1::sign::CoseSign1CreateOutput;
use crate::sign1::verify::{VerifiedCoseSign1, VerifiedDetachedCoseSign1};
use crate::wire::{
    cose_operation_result::Result as OperationResultBranch, CoseOperationResult,
    CoseSign1CreateResult, CoseSign1VerifyResult, CoseSignatureAlgorithm, CoseWireResult,
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
    let message = verify_message(output.payload, output.cose_algorithm, output.kid)?;
    Ok(operation_result(OperationResultBranch::Sign1Verify(
        Box::new(message),
    )))
}

pub(crate) fn verified_detached(
    output: VerifiedDetachedCoseSign1,
) -> CoseWireResult<CoseOperationResult> {
    let message = verify_message(
        Zeroizing::new(Vec::new()),
        output.cose_algorithm,
        output.kid,
    )?;
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
    algorithm: NativeCoseSignatureAlgorithm,
    mut kid: Zeroizing<Vec<u8>>,
) -> CoseWireResult<CoseSign1VerifyResult> {
    Ok(CoseSign1VerifyResult {
        payload: core::mem::take(&mut *payload),
        algorithm: EnumValue::from(legacy_signature_algorithm_to_proto(algorithm)),
        kid: core::mem::take(&mut *kid),
        exact_signature_algorithm: EnumValue::from(signature_algorithm_to_proto(algorithm)?),
        has_exact_signature_algorithm: true,
        __buffa_unknown_fields: Default::default(),
    })
}

fn operation_result(result: OperationResultBranch) -> CoseOperationResult {
    CoseOperationResult {
        result: Some(result),
        __buffa_unknown_fields: Default::default(),
    }
}

pub(crate) fn signature_algorithm_to_proto(
    algorithm: NativeCoseSignatureAlgorithm,
) -> CoseWireResult<CoseSignatureAlgorithm> {
    match algorithm {
        NativeCoseSignatureAlgorithm::Ed25519 => Ok(CoseSignatureAlgorithm::Ed25519),
        NativeCoseSignatureAlgorithm::Es256 => Ok(CoseSignatureAlgorithm::Es256),
        NativeCoseSignatureAlgorithm::Esp256 => Ok(CoseSignatureAlgorithm::Esp256),
        NativeCoseSignatureAlgorithm::Esp384 => Ok(CoseSignatureAlgorithm::Esp384),
        NativeCoseSignatureAlgorithm::Esp512 => Ok(CoseSignatureAlgorithm::Esp512),
        NativeCoseSignatureAlgorithm::Es256K => Ok(CoseSignatureAlgorithm::EcdsaSecp256k1Sha256),
        NativeCoseSignatureAlgorithm::MlDsa44 => Ok(CoseSignatureAlgorithm::MlDsa44),
        NativeCoseSignatureAlgorithm::MlDsa65 => Ok(CoseSignatureAlgorithm::MlDsa65),
        NativeCoseSignatureAlgorithm::MlDsa87 => Ok(CoseSignatureAlgorithm::MlDsa87),
    }
}

fn legacy_signature_algorithm_to_proto(
    algorithm: NativeCoseSignatureAlgorithm,
) -> CoseSignatureAlgorithm {
    match algorithm {
        NativeCoseSignatureAlgorithm::Ed25519 => CoseSignatureAlgorithm::Ed25519,
        NativeCoseSignatureAlgorithm::Es256 | NativeCoseSignatureAlgorithm::Esp256 => {
            CoseSignatureAlgorithm::EcdsaP256Sha256
        }
        NativeCoseSignatureAlgorithm::Esp384 => CoseSignatureAlgorithm::EcdsaP384Sha384,
        NativeCoseSignatureAlgorithm::Esp512 => CoseSignatureAlgorithm::EcdsaP521Sha512,
        NativeCoseSignatureAlgorithm::Es256K => CoseSignatureAlgorithm::EcdsaSecp256k1Sha256,
        NativeCoseSignatureAlgorithm::MlDsa44 => CoseSignatureAlgorithm::MlDsa44,
        NativeCoseSignatureAlgorithm::MlDsa65 => CoseSignatureAlgorithm::MlDsa65,
        NativeCoseSignatureAlgorithm::MlDsa87 => CoseSignatureAlgorithm::MlDsa87,
    }
}
