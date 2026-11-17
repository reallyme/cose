// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{
    self as contract, __buffa::oneof::cose_operation_result::Result as Branch,
};
use crate::wire::{CoseOperationResult, CoseWireError, CoseWireResult};
pub(crate) fn attach(
    request: contract::CoseCounterSignatureAttachRequest,
) -> CoseWireResult<CoseOperationResult> {
    crate::messages::attach_counter_signature::attach(&request)
        .map(|result| {
            super::profile_result::operation(Branch::CounterSignatureAttach(Box::new(result)))
        })
        .map_err(|error| CoseWireError::from_reason(error.reason()))
}
