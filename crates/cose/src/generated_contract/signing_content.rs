// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Borrowed compatibility view of the Buffa CoseContentMode contract.
pub enum SigningContent<'a> {
    /// Canonical CoseContentMode alternative: COSE_CONTENT_MODE_ATTACHED.
    Attached(&'a [u8]),
    /// Canonical CoseContentMode alternative: COSE_CONTENT_MODE_DETACHED.
    Detached(&'a [u8]),
}
