// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{cose_operation_result::Result as Branch, CoseRsaSign1VerifyRequest};
use crate::wire::{CoseOperationResult, CoseWireError, CoseWireResult};

pub(crate) fn verify(request: CoseRsaSign1VerifyRequest) -> CoseWireResult<CoseOperationResult> {
    crate::messages::rsa_sign1::verify(&request)
        .map(|result| super::profile_result::operation(Branch::RsaSign1Verify(Box::new(result))))
        .map_err(|error| CoseWireError::from_reason(error.reason()))
}
