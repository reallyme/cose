// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Borrowed compatibility view of the Buffa CoseKeySource contract.
pub enum VerificationSource<'a> {
    /// Canonical CoseKeySource alternative: COSE_KEY_SOURCE_DIRECT, COSE_KEY_SOURCE_PROVIDER.
    Key(&'a dyn crate::containers::VerificationKey),
    /// Canonical CoseKeySource alternative: COSE_KEY_SOURCE_CERTIFICATES.
    Certificates(&'a dyn crate::containers::CertificateValidator),
}
