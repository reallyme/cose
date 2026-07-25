// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
    let cose_encrypt = Zeroizing::new(core::mem::take(&mut request.cose_encrypt));
    let recipient_private_key = Zeroizing::new(core::mem::take(&mut request.recipient_private_key));
    let expected_recipient_kid =
        Zeroizing::new(core::mem::take(&mut request.expected_recipient_kid));
    let external_aad = Zeroizing::new(core::mem::take(&mut request.external_aad));
    let supp_priv_info = Zeroizing::new(core::mem::take(&mut request.supp_priv_info));
    let native_request = CoseMlKemDecryptRequest::new(
        &cose_encrypt,
        &recipient_private_key,
        &expected_recipient_kid,
        request
            .has_supp_priv_info
            .then_some(supp_priv_info.as_slice()),
    );
    let decrypted = decrypt_cose_ml_kem(CoseMlKemDecryptInput::new(&native_request, &external_aad))
        .map_err(boundary_error_from_failure)?;
    Ok(result::decrypted(decrypted))
}
