// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseMlKemDecryptRequest contract.
#[must_use]
#[non_exhaustive]
pub struct CoseMlKemDecryptRequest<'a> {
    /// Projection of CoseMlKemDecryptRequest.cose_encrypt.
    pub(crate) cose_encrypt: &'a [u8],
    /// Projection of CoseMlKemDecryptRequest.recipient_private_key.
    pub(crate) recipient_private_key: &'a [u8],
    /// Projection of CoseMlKemDecryptRequest.expected_recipient_kid.
    pub(crate) expected_recipient_kid: &'a [u8],
    /// Projection of CoseMlKemDecryptRequest.supp_priv_info.
    pub(crate) supp_priv_info: Option<&'a [u8]>,
}
