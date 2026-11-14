// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseContainerVerifyResult contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderProvenance {
    /// Projection of CoseContainerVerifyResult.chain_placement.
    pub chain_placement: Option<super::X5ChainHeaderPlacement>,
    /// Projection of CoseContainerVerifyResult.protected_thumbprint.
    pub protected_thumbprint: bool,
    /// Projection of CoseContainerVerifyResult.end_entity_integrity.
    pub end_entity_integrity: super::EndEntityIntegrity,
}
