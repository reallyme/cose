// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::wire::CoseWireError;
use crate::CoseError;

pub(crate) fn container(error: CoseError) -> CoseWireError {
    CoseWireError::from_reason(error.reason())
}
pub(crate) fn mac0(error: CoseError) -> CoseWireError {
    CoseWireError::from_reason(error.reason())
}
