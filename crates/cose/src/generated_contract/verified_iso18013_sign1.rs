// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseIsoSign1VerifyResult contract.
pub struct VerifiedIso18013Sign1 {
    /// Projection of CoseIsoSign1VerifyResult.suite.
    pub(crate) suite: super::SignatureSuite,
    /// Projection of CoseIsoSign1VerifyResult.protected_headers.
    pub(crate) protected: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CoseIsoSign1VerifyResult.protected_kid.
    pub(crate) protected_kid: Option<zeroize::Zeroizing<Vec<u8>>>,
    /// Projection of CoseIsoSign1VerifyResult.attached_payload.
    pub(crate) payload: Option<zeroize::Zeroizing<Vec<u8>>>,
}

impl zeroize::ZeroizeOnDrop for VerifiedIso18013Sign1 {}
