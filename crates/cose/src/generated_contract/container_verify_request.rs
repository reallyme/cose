// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseContainerVerifyRequest contract.
pub struct ContainerVerifyRequest<'a> {
    /// Projection of CoseContainerVerifyRequest.encoded.
    pub encoded: &'a [u8],
    /// Projection of CoseContainerVerifyRequest.content_mode, detached_payload.
    pub content: crate::containers::ContainerContent<'a>,
    /// Projection of CoseContainerVerifyRequest.external_aad.
    pub external_aad: &'a [u8],
    /// Projection of CoseContainerVerifyRequest.policy.
    pub policy: super::ContainerPolicy,
    /// Projection of CoseContainerVerifyRequest.allowed_suites.
    pub allowed_suites: &'a [super::SignatureSuite],
    /// Projection of CoseContainerVerifyRequest.limits.
    pub limits: super::ContainerLimits,
}
