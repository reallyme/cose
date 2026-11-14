// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated results own their fields; no borrowed or non-zeroizing DTO copies.

use crate::containers::PeerPointEncoding;
use crate::wire::{
    cose_operation_result::Result as Branch, CoseOperationResult, CosePointEncoding,
};

pub(crate) fn operation(result: Branch) -> CoseOperationResult {
    CoseOperationResult {
        result: Some(result),
    }
}

pub(crate) fn encoding(value: PeerPointEncoding) -> CosePointEncoding {
    CosePointEncoding::from(value)
}
