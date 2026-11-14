// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseMac0VerifyRequest contract.
pub struct CoseMac0VerifyRequest<'a> {
    /// Projection of CoseMac0VerifyRequest.encoded.
    pub encoded: &'a [u8],
    /// Projection of CoseMac0VerifyRequest.detached_payload.
    pub detached_payload: &'a [u8],
    /// Projection of CoseMac0VerifyRequest.external_aad.
    pub external_aad: &'a [u8],
    /// Projection of CoseMac0VerifyRequest.allowed_algorithms.
    pub allowed_algorithms: &'a [super::CoseMacAlgorithm],
    /// Projection of CoseMac0VerifyRequest.limits.
    pub limits: super::ContainerLimits,
}
