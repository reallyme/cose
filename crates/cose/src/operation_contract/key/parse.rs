// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Protobuf adapter for the canonical COSE_Key parse operation.

use zeroize::{Zeroize, Zeroizing};

use crate::key::{parse_cose_key, CoseKeyParseInput};
use crate::operation_contract::key::result;
use crate::operation_contract::map_failure::boundary_error_from_failure;
use crate::wire::{CoseKeyBytesRequest, CoseOperationResult, CoseWireResult};

pub(crate) fn result(mut request: CoseKeyBytesRequest) -> CoseWireResult<CoseOperationResult> {
    // Transfer generated storage immediately into a zeroizing owner. The
    // semantic input borrows this allocation and cannot outlive it.
    let encoded_key = Zeroizing::new(core::mem::take(&mut request.cose_key));
    request.cose_key.zeroize();

    let output = parse_cose_key(CoseKeyParseInput::new(&encoded_key))
        .map_err(boundary_error_from_failure)?;
    result::parsed_key(output)
}
