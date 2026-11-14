// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseMlKemDecryptResult contract.
#[must_use]
#[non_exhaustive]
pub struct DecryptedCoseEncrypt {
    /// Projection of CoseMlKemDecryptResult.plaintext.
    pub plaintext: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CoseMlKemDecryptResult.content_algorithm.
    pub content_algorithm: super::CoseContentEncryptionAlgorithm,
    /// Projection of CoseMlKemDecryptResult.kem_algorithm.
    pub kem_algorithm: super::CoseMlKemAlgorithm,
    /// Projection of CoseMlKemDecryptResult.mode.
    pub mode: super::CoseMlKemMode,
    /// Projection of CoseMlKemDecryptResult.recipient_kid.
    pub kid: zeroize::Zeroizing<Vec<u8>>,
    /// Projection of CoseMlKemDecryptResult.profile.
    pub profile: super::CoseMlKemProfile,
}

impl zeroize::ZeroizeOnDrop for DecryptedCoseEncrypt {}
