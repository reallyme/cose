// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{
    self as contract, __buffa::oneof::cose_operation_result::Result as Branch,
};
use crate::wire::{CoseOperationResult, CoseWireError, CoseWireResult};

pub(crate) fn parse(
    request: contract::CoseKeySetParseRequest,
) -> CoseWireResult<CoseOperationResult> {
    crate::messages::key_set::parse(&request)
        .map(|result| super::profile_result::operation(Branch::KeySetParse(Box::new(result))))
        .map_err(|error| CoseWireError::from_reason(error.reason()))
}

pub(crate) fn create(
    request: contract::CoseKeySetCreateRequest,
) -> CoseWireResult<CoseOperationResult> {
    crate::messages::key_set::create(&request)
        .map(|result| super::profile_result::operation(Branch::KeySetCreate(Box::new(result))))
        .map_err(|error| CoseWireError::from_reason(error.reason()))
}
