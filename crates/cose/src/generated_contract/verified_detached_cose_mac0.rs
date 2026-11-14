// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseMac0VerifyResult contract.
pub struct VerifiedDetachedCoseMac0 {
    /// Projection of CoseMac0VerifyResult.algorithm.
    pub(crate) algorithm: super::CoseMacAlgorithm,
    /// Projection of CoseMac0VerifyResult.protected_headers.
    pub(crate) protected_bytes: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CoseMac0VerifyResult.protected_kid.
    pub(crate) protected_kid: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl zeroize::ZeroizeOnDrop for VerifiedDetachedCoseMac0 {}
