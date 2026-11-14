// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Borrowed compatibility view of the Buffa CoseIsoSign1Content contract.
pub enum Iso18013Sign1Content<'a> {
    /// Canonical CoseIsoSign1Content alternative: COSE_ISO_SIGN1_CONTENT_ISSUER_ATTACHED.
    IssuerAttached,
    /// Canonical CoseIsoSign1Content alternative: COSE_ISO_SIGN1_CONTENT_DEVICE_DETACHED.
    DeviceDetached(&'a [u8]),
    /// Canonical CoseIsoSign1Content alternative: COSE_ISO_SIGN1_CONTENT_READER_DETACHED.
    ReaderDetached(&'a [u8]),
}
