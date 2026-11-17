// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::sign1::build_sign1_signature_structure;
use crate::wire::{
    cose_operation_result::Result as Branch, CoseOperationResult,
    CoseSign1SignatureStructureRequest, CoseSign1SignatureStructureResult, CoseWireError,
    CoseWireResult,
};

pub(crate) fn build(
    request: CoseSign1SignatureStructureRequest,
) -> CoseWireResult<CoseOperationResult> {
    // A budget above this platform's address space covers all representable
    // outputs. Transport admission still bounds the aggregate request bytes.
    let maximum = usize::try_from(request.max_output_bytes).unwrap_or(usize::MAX);
    let mut structure = build_sign1_signature_structure(
        &request.protected,
        &request.external_aad,
        &request.payload,
        maximum,
    )
    .map_err(|error| CoseWireError::from_reason(error.reason()))?;
    Ok(super::profile_result::operation(
        Branch::Sign1SignatureStructure(Box::new(CoseSign1SignatureStructureResult {
            signature_structure: core::mem::take(&mut *structure).into(),
        })),
    ))
}
