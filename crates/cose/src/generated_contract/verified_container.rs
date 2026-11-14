// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseContainerVerifyResult contract.
pub struct VerifiedContainer {
    /// Projection of CoseContainerVerifyResult.policy.
    pub(crate) policy: super::ContainerPolicy,
    /// Projection of CoseContainerVerifyResult.key.suite.
    pub(crate) suite: super::SignatureSuite,
    /// Projection of CoseContainerVerifyResult.chain_placement, protected_thumbprint, end_entity_integrity.
    pub(crate) provenance: super::HeaderProvenance,
    /// Projection of CoseContainerVerifyResult.encoded.
    pub(crate) encoded: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CoseContainerVerifyResult.protected_headers.
    pub(crate) protected: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CoseContainerVerifyResult.unprotected_headers.
    pub(crate) unprotected: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CoseContainerVerifyResult.payload.
    pub(crate) payload: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CoseContainerVerifyResult.key.public_key.
    pub(crate) public_key: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CoseContainerVerifyResult.key.context_id.
    pub(crate) context: zeroize::Zeroizing<[u8; 32]>,
    /// Projection of CoseContainerVerifyResult.certificate_sha256.
    pub(crate) certificate_digest: Option<zeroize::Zeroizing<[u8; 32]>>,
}

impl zeroize::ZeroizeOnDrop for VerifiedContainer {}
