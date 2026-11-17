// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{
    self as contract, __buffa::oneof::cose_operation_result::Result as Branch,
};
use crate::wire::{CoseOperationResult, CoseWireError, CoseWireResult};
pub(crate) fn create(
    request: contract::CoseEncrypt0CreateRequest,
) -> CoseWireResult<CoseOperationResult> {
    crate::messages::encrypt0::create(&request)
        .map(|result| super::profile_result::operation(Branch::Encrypt0Create(Box::new(result))))
        .map_err(|error| CoseWireError::from_reason(error.reason()))
}
pub(crate) fn decrypt(
    request: contract::CoseEncrypt0DecryptRequest,
) -> CoseWireResult<CoseOperationResult> {
    crate::messages::encrypt0::decrypt(&request)
        .map(|result| super::profile_result::operation(Branch::Encrypt0Decrypt(Box::new(result))))
        .map_err(|error| CoseWireError::from_reason(error.reason()))
}
