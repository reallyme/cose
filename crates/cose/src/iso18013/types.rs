// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use super::Iso18013SignatureSuite;

/// Role-specific ISO authentication content; external AAD is always empty.
pub use crate::generated_contract::Iso18013Sign1Content;

/// Compatibility name for the shared byte-limit contract.
pub use crate::containers::ContainerLimits as Iso18013Sign1Limits;

/// Inputs for explicitly authorized ISO/IEC 18013-5:2021 Sign1 verification.
///
/// Original input owners remain responsible for clearing sensitive data. The
/// verifier wipes all owned decoding and authentication-structure copies.
pub use crate::generated_contract::Iso18013Sign1Request;

/// Authenticated ISO Sign1 metadata and optional attached issuer payload.
///
/// Contains no unprotected header hints or certificate-trust assertions. All
/// owned identifier, header, and payload bytes wipe on drop. No formatting,
/// cloning, or serialization implementations expose identifying content.
pub use crate::generated_contract::VerifiedIso18013Sign1;

impl VerifiedIso18013Sign1 {
    /// Return the exact authenticated registration and validated key curve.
    #[must_use]
    pub const fn suite(&self) -> Iso18013SignatureSuite {
        self.suite
    }

    /// Return the protected header bytes exactly as authenticated.
    #[must_use]
    pub fn protected_header_bytes(&self) -> &[u8] {
        &self.protected
    }

    /// Return only an authenticated protected key identifier, if present.
    #[must_use]
    pub fn protected_key_id(&self) -> Option<&[u8]> {
        self.protected_kid.as_ref().map(|kid| kid.as_slice())
    }

    /// Return the authenticated attached issuer payload; detached roles return none.
    #[must_use]
    pub fn attached_payload(&self) -> Option<&[u8]> {
        self.payload.as_ref().map(|payload| payload.as_slice())
    }
}
