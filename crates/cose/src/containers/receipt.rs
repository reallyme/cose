// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ContainerPolicy, SignatureSuite};

/// Closed compatibility view generated from the protobuf selector.
pub use crate::generated_contract::EndEntityIntegrity;

/// Header origin and cryptographic integrity, independently of certificate trust.
pub use crate::generated_contract::HeaderProvenance;

/// Authenticated byte owners and actual verification context, released on success only.
///
/// This receipt establishes a signature under the supplied capability. It is
/// never an independent certificate-path, authority, freshness or schema verdict.
/// Identifying bytes are wiped on drop; formatting, cloning and serialization
/// are deliberately unavailable.
pub use crate::generated_contract::VerifiedContainer;

impl VerifiedContainer {
    /// Exact original complete envelope.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
    /// Exact protected-header bytes authenticated in Sig_structure.
    #[must_use]
    pub fn protected_headers(&self) -> &[u8] {
        &self.protected
    }
    /// Exact unprotected map, including bounded unknown noncritical headers.
    /// This span itself is not authenticated by the signature.
    #[must_use]
    pub fn unprotected_headers(&self) -> &[u8] {
        &self.unprotected
    }
    /// Exact authenticated attached or caller-supplied detached payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Selected baseline, purpose and envelope contract.
    #[must_use]
    pub const fn policy(&self) -> ContainerPolicy {
        self.policy
    }
    /// Actual effective key's exact suite.
    #[must_use]
    pub const fn suite(&self) -> SignatureSuite {
        self.suite
    }
    /// Explicit placement and end-entity integrity provenance.
    #[must_use]
    pub const fn provenance(&self) -> HeaderProvenance {
        self.provenance
    }
    /// Actual validated public key used by the verification capability.
    #[must_use]
    pub fn verification_public_key(&self) -> &[u8] {
        &self.public_key
    }
    /// Actual external verification context supplied by the capability.
    #[must_use]
    pub fn verification_context(&self) -> &[u8; 32] {
        &self.context
    }
    /// SHA-256 of the exact certificate selected by the certificate boundary.
    #[must_use]
    pub fn selected_certificate_sha256(&self) -> Option<&[u8; 32]> {
        self.certificate_digest.as_deref()
    }
}
