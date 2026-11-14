// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated-contract adapters for direct and AES-KW ML-KEM encryption.

use zeroize::Zeroizing;

use crate::encrypt::create::{
    encrypt_cose_ml_kem_direct, encrypt_cose_ml_kem_key_wrap, CoseMlKemEncryptOutput,
};
use crate::encrypt::types::{CoseMlKemEncryptInput, CoseMlKemEncryptRequest};
use crate::failure::CoseFailure;
use crate::operation_contract::encrypt::result;
use crate::operation_contract::input::{content_algorithm_from_proto, ml_kem_algorithm_from_proto};
use crate::operation_contract::map_failure::boundary_error_from_failure;
use crate::wire::{
    CoseMlKemEncryptRequest as ProtoEncryptRequest, CoseOperationResult, CoseWireResult,
};

pub(crate) fn direct_result(request: ProtoEncryptRequest) -> CoseWireResult<CoseOperationResult> {
    encrypt_result(
        request,
        encrypt_cose_ml_kem_direct,
        result::encrypted_direct,
    )
}

pub(crate) fn key_wrap_result(request: ProtoEncryptRequest) -> CoseWireResult<CoseOperationResult> {
    encrypt_result(
        request,
        encrypt_cose_ml_kem_key_wrap,
        result::encrypted_key_wrap,
    )
}

fn encrypt_result(
    mut request: ProtoEncryptRequest,
    operation: for<'request, 'aad> fn(
        CoseMlKemEncryptInput<'request, 'aad>,
    ) -> Result<CoseMlKemEncryptOutput, CoseFailure>,
    convert_result: fn(CoseMlKemEncryptOutput) -> CoseOperationResult,
) -> CoseWireResult<CoseOperationResult> {
    let recipient_public_key = core::mem::take(&mut request.recipient_public_key).into_zeroizing();
    let recipient_kid = core::mem::take(&mut request.recipient_kid).into_zeroizing();
    let plaintext = core::mem::take(&mut request.plaintext).into_zeroizing();
    let external_aad = core::mem::take(&mut request.external_aad).into_zeroizing();
    let supp_priv_info = Zeroizing::new(core::mem::take(&mut request.supp_priv_info));
    let native_request = CoseMlKemEncryptRequest::new(
        ml_kem_algorithm_from_proto(request.kem_algorithm)?,
        content_algorithm_from_proto(request.content_algorithm)?,
        &recipient_public_key,
        &recipient_kid,
        &plaintext,
        supp_priv_info.as_deref(),
    );
    let input = CoseMlKemEncryptInput::new(&native_request, &external_aad);
    let output = operation(input).map_err(boundary_error_from_failure)?;
    Ok(convert_result(output))
}
