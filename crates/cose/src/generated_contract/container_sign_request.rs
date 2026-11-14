// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseContainerSignRequest contract.
pub struct ContainerSignRequest<'a> {
    /// Projection of CoseContainerSignRequest.protected_headers.
    pub protected_headers: &'a [u8],
    /// Projection of CoseContainerSignRequest.unprotected_headers.
    pub unprotected_headers: &'a [u8],
    /// Projection of CoseContainerSignRequest.content_mode, payload.
    pub content: crate::containers::SigningContent<'a>,
    /// Projection of CoseContainerSignRequest.external_aad.
    pub external_aad: &'a [u8],
    /// Projection of CoseContainerSignRequest.policy.
    pub policy: super::ContainerPolicy,
    /// Projection of CoseContainerSignRequest.allowed_suites.
    pub allowed_suites: &'a [super::SignatureSuite],
    /// Projection of CoseContainerSignRequest.limits.
    pub limits: super::ContainerLimits,
}
