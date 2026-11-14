// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

/// Native compatibility projection of the Buffa CoseOpaqueBytes contract.
pub struct SignedContainer {
    /// Projection of CoseOpaqueBytes.encoded.
    pub(crate) encoded: zeroize::Zeroizing<Vec<u8>>,
}

impl zeroize::ZeroizeOnDrop for SignedContainer {}
