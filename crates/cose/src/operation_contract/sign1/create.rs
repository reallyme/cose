// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Generated-contract adapters for attached and detached COSE_Sign1 creation.

use zeroize::Zeroizing;

use crate::operation_contract::input::{encode_options_from_proto, signature_algorithm_from_proto};
use crate::operation_contract::map_failure::boundary_error_from_failure;
use crate::operation_contract::sign1::result;
use crate::sign1::sign::{create_cose_sign1, create_detached_cose_sign1};
use crate::sign1::types::CoseSign1CreateInput;
use crate::wire::{
    CoseOperationResult, CoseSign1CreateDetachedRequest, CoseSign1CreateRequest, CoseWireResult,
};

pub(crate) fn attached_result(
    mut request: CoseSign1CreateRequest,
) -> CoseWireResult<CoseOperationResult> {
    let payload = Zeroizing::new(core::mem::take(&mut request.payload));
    let private_key = Zeroizing::new(core::mem::take(&mut request.private_key));
    let kid = Zeroizing::new(core::mem::take(&mut request.kid));
    let external_aad = Zeroizing::new(core::mem::take(&mut request.external_aad));
    let algorithm = signature_algorithm_from_proto(request.algorithm)?;
    let options = encode_options_from_proto(request.options.as_option())?;
    let kid = request.has_kid.then_some(kid.as_slice());
    let result = create_cose_sign1(CoseSign1CreateInput::new(
        algorithm,
        &payload,
        &private_key,
        kid,
        &external_aad,
        options,
    ))
    .map_err(boundary_error_from_failure)?;
    Ok(result::created_attached(result))
}

pub(crate) fn detached_result(
    mut request: CoseSign1CreateDetachedRequest,
) -> CoseWireResult<CoseOperationResult> {
    let payload = Zeroizing::new(core::mem::take(&mut request.payload));
    let private_key = Zeroizing::new(core::mem::take(&mut request.private_key));
    let kid = Zeroizing::new(core::mem::take(&mut request.kid));
    let external_aad = Zeroizing::new(core::mem::take(&mut request.external_aad));
    let algorithm = signature_algorithm_from_proto(request.algorithm)?;
    let options = encode_options_from_proto(request.options.as_option())?;
    let kid = request.has_kid.then_some(kid.as_slice());
    let result = create_detached_cose_sign1(CoseSign1CreateInput::new(
        algorithm,
        &payload,
        &private_key,
        kid,
        &external_aad,
        options,
    ))
    .map_err(boundary_error_from_failure)?;
    Ok(result::created_detached(result))
}
