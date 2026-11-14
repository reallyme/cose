// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Borrowed compatibility view of the Buffa CoseSigningInput contract.
pub enum SigningInput<'a> {
    /// Canonical CoseSigningInput alternative: message.
    Message(&'a [u8]),
    /// Canonical CoseSigningInput alternative: ecdsa_prehash.
    EcdsaPrehash {
        /// Canonical CoseSigningInput.ecdsa_prehash.hash field.
        hash: super::Iso18013EcdsaHash,
        /// Canonical CoseSigningInput.ecdsa_prehash.digest field.
        digest: &'a [u8],
    },
}
