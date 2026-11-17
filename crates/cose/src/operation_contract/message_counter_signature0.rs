// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{
    self as contract, __buffa::oneof::cose_operation_result::Result as Branch,
};
use crate::wire::{CoseOperationResult, CoseWireError, CoseWireResult};
pub(crate) fn create(
    request: contract::CoseCounterSignature0CreateRequest,
) -> CoseWireResult<CoseOperationResult> {
    crate::messages::counter_signature0::create(&request)
        .map(|result| {
            super::profile_result::operation(Branch::CounterSignature0Create(Box::new(result)))
        })
        .map_err(|error| CoseWireError::from_reason(error.reason()))
}
pub(crate) fn verify(
    request: contract::CoseCounterSignature0VerifyRequest,
) -> CoseWireResult<CoseOperationResult> {
    crate::messages::counter_signature0::verify(&request)
        .map(|result| {
            super::profile_result::operation(Branch::CounterSignature0Verify(Box::new(result)))
        })
        .map_err(|error| CoseWireError::from_reason(error.reason()))
}
