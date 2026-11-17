// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{
    self as contract, __buffa::oneof::cose_operation_result::Result as Branch,
};
use crate::wire::{CoseOperationResult, CoseWireError, CoseWireResult};
pub(crate) fn create(
    request: contract::CoseMacCreateRequest,
) -> CoseWireResult<CoseOperationResult> {
    crate::messages::mac::create(&request)
        .map(|result| super::profile_result::operation(Branch::MacCreate(Box::new(result))))
        .map_err(|error| CoseWireError::from_reason(error.reason()))
}
pub(crate) fn verify(
    request: contract::CoseMacVerifyRequest,
) -> CoseWireResult<CoseOperationResult> {
    crate::messages::mac::verify(&request)
        .map(|result| super::profile_result::operation(Branch::MacVerify(Box::new(result))))
        .map_err(|error| CoseWireError::from_reason(error.reason()))
}
