// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict signature representation operations; no encoding heuristics.

use super::map_profile_failure::container as boundary_error_from_failure;
use crate::containers::{
    cose_signature_to_der_operation, signature_to_cose_operation,
    validate_cose_signature_operation, ContainerErrorReason as Reason, SignatureEncoding,
};
use crate::wire::{
    cose_operation_result::Result as Branch, CoseOpaqueBytes, CoseOperationResult,
    CoseSignatureConvertRequest, CoseSignatureEncoding, CoseWireResult,
};

pub(crate) fn to_cose(request: CoseSignatureConvertRequest) -> CoseWireResult<CoseOperationResult> {
    let curve = super::profile_input::curve(request.curve).map_err(boundary_error_from_failure)?;
    let encoding = match request.encoding.as_known() {
        Some(CoseSignatureEncoding::CoseEcdsa) => SignatureEncoding::EcdsaFixed,
        Some(CoseSignatureEncoding::EcdsaDer) => SignatureEncoding::EcdsaDer,
        Some(CoseSignatureEncoding::Eddsa) => SignatureEncoding::EdDsa,
        _ => {
            return Err(boundary_error_from_failure(
                Reason::SignatureEncoding.into(),
            ))
        }
    };
    let mut output = signature_to_cose_operation(curve, encoding, &request.signature)
        .map_err(boundary_error_from_failure)?;
    Ok(super::profile_result::operation(Branch::SignatureToCose(
        Box::new(CoseOpaqueBytes {
            encoded: core::mem::take(&mut *output).into(),
        }),
    )))
}

pub(crate) fn to_der(request: CoseSignatureConvertRequest) -> CoseWireResult<CoseOperationResult> {
    if request.encoding.as_known() != Some(CoseSignatureEncoding::CoseEcdsa) {
        return Err(boundary_error_from_failure(
            Reason::SignatureEncoding.into(),
        ));
    }
    let curve = super::profile_input::curve(request.curve).map_err(boundary_error_from_failure)?;
    let mut output = cose_signature_to_der_operation(curve, &request.signature)
        .map_err(boundary_error_from_failure)?;
    Ok(super::profile_result::operation(Branch::SignatureToDer(
        Box::new(CoseOpaqueBytes {
            encoded: core::mem::take(&mut *output).into(),
        }),
    )))
}

pub(crate) fn validate(
    request: CoseSignatureConvertRequest,
) -> CoseWireResult<CoseOperationResult> {
    let curve = super::profile_input::curve(request.curve).map_err(boundary_error_from_failure)?;
    let expected = if curve.coordinate_length().is_some() {
        CoseSignatureEncoding::CoseEcdsa
    } else {
        CoseSignatureEncoding::Eddsa
    };
    if request.encoding.as_known() != Some(expected) {
        return Err(boundary_error_from_failure(
            Reason::SignatureEncoding.into(),
        ));
    }
    validate_cose_signature_operation(curve, &request.signature)
        .map_err(boundary_error_from_failure)?;
    Ok(super::profile_result::operation(Branch::SignatureValidate(
        Box::default(),
    )))
}

pub(crate) fn preferred_cbor(request: CoseOpaqueBytes) -> CoseWireResult<CoseOperationResult> {
    crate::containers::validate_preferred_cbor_operation(&request.encoded)
        .map_err(boundary_error_from_failure)?;
    Ok(super::profile_result::operation(
        Branch::PreferredCborValidate(Box::default()),
    ))
}
