// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseMlKemEncryptRequest contract.
#[must_use]
#[non_exhaustive]
pub struct CoseMlKemEncryptRequest<'a> {
    /// Projection of CoseMlKemEncryptRequest.kem_algorithm.
    pub(crate) kem_algorithm: super::CoseMlKemAlgorithm,
    /// Projection of CoseMlKemEncryptRequest.content_algorithm.
    pub(crate) content_algorithm: super::CoseContentEncryptionAlgorithm,
    /// Projection of CoseMlKemEncryptRequest.recipient_public_key.
    pub(crate) recipient_public_key: &'a [u8],
    /// Projection of CoseMlKemEncryptRequest.recipient_kid.
    pub(crate) recipient_kid: &'a [u8],
    /// Projection of CoseMlKemEncryptRequest.plaintext.
    pub(crate) plaintext: &'a [u8],
    /// Projection of CoseMlKemEncryptRequest.supp_priv_info.
    pub(crate) supp_priv_info: Option<&'a [u8]>,
}
