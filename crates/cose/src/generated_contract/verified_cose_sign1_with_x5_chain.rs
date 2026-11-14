// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseSign1X5ChainResult contract.
#[must_use]
#[non_exhaustive]
pub struct VerifiedCoseSign1WithX5Chain {
    /// Projection of CoseSign1X5ChainResult.verified.payload.
    pub payload: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CoseSign1X5ChainResult.verified.algorithm.
    pub alg: reallyme_crypto::core::Algorithm,
    /// Projection of CoseSign1X5ChainResult.verified.exact_signature_algorithm.
    pub cose_algorithm: super::CoseSignatureAlgorithm,
    /// Projection of CoseSign1X5ChainResult.verified.kid.
    pub kid: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CoseSign1X5ChainResult.verified.protected_type.
    pub cose_type: Option<crate::policy::typ::CoseType>,
    /// Projection of CoseSign1X5ChainResult.x5chain.certificates_der.
    pub x5chain_der: zeroize::Zeroizing<Vec<Vec<u8>>>,
    /// Projection of CoseSign1X5ChainResult.placement.
    pub x5chain_header_placement: super::X5ChainHeaderPlacement,
}

impl zeroize::ZeroizeOnDrop for VerifiedCoseSign1WithX5Chain {}
