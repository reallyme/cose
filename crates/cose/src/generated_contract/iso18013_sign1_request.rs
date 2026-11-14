// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseIsoSign1VerifyRequest contract.
pub struct Iso18013Sign1Request<'a> {
    /// Projection of CoseIsoSign1VerifyRequest.encoded.
    pub encoded: &'a [u8],
    /// Projection of CoseIsoSign1VerifyRequest.content, detached_payload.
    pub content: crate::iso18013::Iso18013Sign1Content<'a>,
    /// Projection of CoseIsoSign1VerifyRequest.allowed_suites.
    pub allowed_suites: &'a [super::SignatureSuite],
    /// Projection of CoseIsoSign1VerifyRequest.limits.
    pub limits: super::ContainerLimits,
}
