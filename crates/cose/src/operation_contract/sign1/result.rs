// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated-result conversion for COSE_Sign1 operations.

use buffa::{EnumValue, MessageField};
use zeroize::Zeroizing;

use crate::algorithm::CoseSignatureAlgorithm as NativeCoseSignatureAlgorithm;
use crate::sign1::sign::CoseSign1CreateOutput;
use crate::sign1::verify::{VerifiedCoseSign1, VerifiedDetachedCoseSign1};
use crate::sign1::CoseType as NativeCoseType;
use crate::wire::{
    cose_operation_result::Result as OperationResultBranch, CoseOperationResult,
    CoseSign1CreateResult, CoseSign1VerifyResult, CoseSignatureAlgorithm, CoseType as WireCoseType,
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
    let message = verify_message(
        output.payload,
        output.cose_algorithm,
        output.kid,
        output.cose_type,
    )?;
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
        output.cose_type,
    )?;
    Ok(operation_result(
        OperationResultBranch::Sign1VerifyDetached(Box::new(message)),
    ))
}

fn create_message(output: CoseSign1CreateOutput) -> CoseSign1CreateResult {
    let mut cose_sign1 = output.into_zeroizing();
    CoseSign1CreateResult {
        cose_sign1: core::mem::take(&mut *cose_sign1).into(),
    }
}

pub(crate) fn verify_message(
    mut payload: Zeroizing<Vec<u8>>,
    algorithm: NativeCoseSignatureAlgorithm,
    mut kid: Zeroizing<Vec<u8>>,
    cose_type: Option<NativeCoseType>,
) -> CoseWireResult<CoseSign1VerifyResult> {
    let protected_type = cose_type.map_or_else(MessageField::none, |value| {
        MessageField::some(WireCoseType { value: Some(value) })
    });
    Ok(CoseSign1VerifyResult {
        payload: core::mem::take(&mut *payload).into(),
        algorithm: EnumValue::from(legacy_signature_algorithm_to_proto(algorithm)),
        kid: core::mem::take(&mut *kid).into(),
        exact_signature_algorithm: EnumValue::from(signature_algorithm_to_proto(algorithm)?),
        protected_type,
    })
}

fn operation_result(result: OperationResultBranch) -> CoseOperationResult {
    CoseOperationResult {
        result: Some(result),
    }
}

pub(crate) fn signature_algorithm_to_proto(
    algorithm: NativeCoseSignatureAlgorithm,
) -> CoseWireResult<CoseSignatureAlgorithm> {
    Ok(CoseSignatureAlgorithm::from(algorithm))
}

// Keep the published compatibility selector alongside the exact registration.
#[allow(deprecated)]
fn legacy_signature_algorithm_to_proto(
    algorithm: NativeCoseSignatureAlgorithm,
) -> CoseSignatureAlgorithm {
    match algorithm {
        NativeCoseSignatureAlgorithm::Es256 | NativeCoseSignatureAlgorithm::Esp256 => {
            CoseSignatureAlgorithm::EcdsaP256Sha256
        }
        NativeCoseSignatureAlgorithm::Esp384 => CoseSignatureAlgorithm::EcdsaP384Sha384,
        NativeCoseSignatureAlgorithm::Esp512 => CoseSignatureAlgorithm::EcdsaP521Sha512,
        other => CoseSignatureAlgorithm::from(other),
    }
}
