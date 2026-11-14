// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use super::Iso18013EcdsaHash;

/// Closed callback view of the schema selector and its explicit payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SigningMode {
    /// Schema-defined Message alternative.
    Message,
    /// Schema-defined EcdsaPrehash alternative.
    EcdsaPrehash(Iso18013EcdsaHash),
}
