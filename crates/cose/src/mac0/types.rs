// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use super::CoseMacAlgorithm;

/// Compatibility name for the shared byte-limit contract.
pub use crate::containers::ContainerLimits as CoseMac0Limits;

/// Explicit inputs to detached MAC verification; an empty allowlist rejects all.
///
/// Borrowed input owners remain responsible for wiping PII. The verifier wipes
/// its decoded copies and MAC_structure, including on authentication failure.
pub use crate::generated_contract::CoseMac0VerifyRequest;

/// Authenticated Mac0 metadata, released only after successful verification.
///
/// Contains neither payload nor key material, and never exposes unprotected
/// headers. Metadata can contain identifiers, so it is wiped on drop and has
/// no formatting, cloning, or serialization implementations.
pub use crate::generated_contract::VerifiedDetachedCoseMac0;

impl VerifiedDetachedCoseMac0 {
    /// Return the authenticated, exact COSE registration.
    #[must_use]
    pub const fn algorithm(&self) -> CoseMacAlgorithm {
        self.algorithm
    }

    /// Return the authenticated protected header byte string without re-encoding.
    #[must_use]
    pub fn protected_header_bytes(&self) -> &[u8] {
        &self.protected_bytes
    }

    /// Return only an authenticated protected `kid`, if present.
    #[must_use]
    pub fn protected_key_id(&self) -> Option<&[u8]> {
        self.protected_kid.as_ref().map(|kid| kid.as_slice())
    }
}
