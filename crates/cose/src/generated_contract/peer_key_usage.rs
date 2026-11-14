// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use super::SignatureSuite;

/// Closed callback view of the schema selector and its explicit payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PeerKeyUsage {
    /// Schema-defined Signature alternative.
    Signature(SignatureSuite),
    /// Schema-defined Agreement alternative.
    Agreement,
    /// Schema-defined HpkeRecipient alternative.
    HpkeRecipient,
}
