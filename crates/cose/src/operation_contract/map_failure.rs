// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::failure::CoseFailure;
use crate::wire::CoseWireError;

pub(crate) fn boundary_error_from_failure(failure: CoseFailure) -> CoseWireError {
    use crate::failure::{CoseFailureBranch as Branch, CoseFailureOrigin as Origin};
    match (failure.origin(), failure.branch()) {
        (Origin::Caller, Branch::Primitive)
        | (Origin::Provider, Branch::Provider)
        | (Origin::Backend, Branch::Backend) => CoseWireError::from_reason(failure.reason()),
        _ => CoseWireError::backend_internal(crate::wire::CoseErrorReason::BackendInternal),
    }
}

impl From<crate::CoseError> for CoseWireError {
    fn from(error: crate::CoseError) -> Self {
        Self::from_reason(error.reason())
    }
}
