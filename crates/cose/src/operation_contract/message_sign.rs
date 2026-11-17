// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{
    self as contract, __buffa::oneof::cose_operation_result::Result as Branch,
};
use crate::wire::{CoseOperationResult, CoseWireError, CoseWireResult};

pub(crate) fn create(
    request: contract::CoseSignCreateRequest,
) -> CoseWireResult<CoseOperationResult> {
    crate::messages::sign::create(&request)
        .map(|result| super::profile_result::operation(Branch::SignCreate(Box::new(result))))
        .map_err(|error| CoseWireError::from_reason(error.reason()))
}
pub(crate) fn verify(
    request: contract::CoseSignVerifyRequest,
) -> CoseWireResult<CoseOperationResult> {
    crate::messages::sign::verify(&request)
        .map(|result| super::profile_result::operation(Branch::SignVerify(Box::new(result))))
        .map_err(|error| CoseWireError::from_reason(error.reason()))
}
