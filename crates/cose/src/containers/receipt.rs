// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ContainerPolicy, SignatureSuite};
use crate::X5ChainHeaderPlacement;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// How the selected end entity was bound to the authenticated content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndEntityIntegrity {
    /// No certificate headers; a separately validated public key was supplied.
    ExternalKey,
    /// Exact DER occurs in protected x5chain.
    ProtectedChain,
    /// Protected SHA-256 x5t matches the exact selected DER certificate.
    ProtectedThumbprint,
    /// Explicit ISO/VICAL interoperability exception for an unprotected chain.
    IsoUnprotectedChain,
}

/// Header origin and cryptographic integrity, independently of certificate trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderProvenance {
    /// Bucket containing the received chain, if any.
    pub chain_placement: Option<X5ChainHeaderPlacement>,
    /// Whether protected SHA-256 x5t was present and matched.
    pub protected_thumbprint: bool,
    /// Exact selected end-entity integrity rule applied.
    pub end_entity_integrity: EndEntityIntegrity,
}

/// Authenticated byte owners and actual verification context, released on success only.
///
/// This receipt establishes a signature under the supplied capability. It is
/// never an independent certificate-path, authority, freshness or schema verdict.
/// Identifying bytes are wiped on drop; formatting, cloning and serialization
/// are deliberately unavailable.
pub struct VerifiedContainer {
    pub(super) policy: ContainerPolicy,
    pub(super) suite: SignatureSuite,
    pub(super) provenance: HeaderProvenance,
    pub(super) encoded: Zeroizing<Vec<u8>>,
    pub(super) protected: Zeroizing<Vec<u8>>,
    pub(super) unprotected: Zeroizing<Vec<u8>>,
    pub(super) payload: Zeroizing<Vec<u8>>,
    pub(super) public_key: Zeroizing<Vec<u8>>,
    pub(super) context: Zeroizing<[u8; 32]>,
    pub(super) certificate_digest: Option<Zeroizing<[u8; 32]>>,
}

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
impl ZeroizeOnDrop for VerifiedContainer {}
