// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated-contract adapter for ML-KEM decryption.

use zeroize::Zeroizing;

use crate::encrypt::decrypt::decrypt_cose_ml_kem;
use crate::encrypt::types::{CoseMlKemDecryptInput, CoseMlKemDecryptRequest};
use crate::operation_contract::encrypt::result;
use crate::operation_contract::map_failure::boundary_error_from_failure;
use crate::wire::{
    CoseMlKemDecryptRequest as ProtoDecryptRequest, CoseOperationResult, CoseWireResult,
};

pub(crate) fn result(mut request: ProtoDecryptRequest) -> CoseWireResult<CoseOperationResult> {
    let cose_encrypt = core::mem::take(&mut request.cose_encrypt).into_zeroizing();
    let recipient_private_key =
        core::mem::take(&mut request.recipient_private_key).into_zeroizing();
    let expected_recipient_kid =
        core::mem::take(&mut request.expected_recipient_kid).into_zeroizing();
    let external_aad = core::mem::take(&mut request.external_aad).into_zeroizing();
    let supp_priv_info = Zeroizing::new(core::mem::take(&mut request.supp_priv_info));
    let native_request = CoseMlKemDecryptRequest::new(
        &cose_encrypt,
        &recipient_private_key,
        &expected_recipient_kid,
        supp_priv_info.as_deref(),
    );
    let decrypted = decrypt_cose_ml_kem(CoseMlKemDecryptInput::new(&native_request, &external_aad))
        .map_err(boundary_error_from_failure)?;
    Ok(result::decrypted(decrypted))
}
