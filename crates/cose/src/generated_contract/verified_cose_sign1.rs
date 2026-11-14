// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseSign1VerifyResult contract.
#[must_use]
#[non_exhaustive]
pub struct VerifiedCoseSign1 {
    /// Projection of CoseSign1VerifyResult.payload.
    pub payload: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CoseSign1VerifyResult.algorithm.
    pub alg: reallyme_crypto::core::Algorithm,
    /// Projection of CoseSign1VerifyResult.exact_signature_algorithm.
    pub cose_algorithm: super::CoseSignatureAlgorithm,
    /// Projection of CoseSign1VerifyResult.kid.
    pub kid: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CoseSign1VerifyResult.protected_type.
    pub cose_type: Option<crate::policy::typ::CoseType>,
}

impl zeroize::ZeroizeOnDrop for VerifiedCoseSign1 {}
