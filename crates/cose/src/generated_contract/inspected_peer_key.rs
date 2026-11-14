// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CosePeerKeyResult contract.
pub struct InspectedPeerKey {
    /// Projection of CosePeerKeyResult.cose_key.
    pub(crate) original: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CosePeerKeyResult.public_key.
    pub(crate) material: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CosePeerKeyResult.curve.
    pub(crate) curve: super::CoseCurve,
    /// Projection of CosePeerKeyResult.purpose, signature_suite.
    pub(crate) usage: super::PeerKeyUsage,
    /// Projection of CosePeerKeyResult.point_encoding.
    pub(crate) encoding: super::CosePointEncoding,
}

impl zeroize::ZeroizeOnDrop for InspectedPeerKey {}
