// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    ContainerError, ContainerErrorReason as Reason, SignatureRegistration, SignatureSuite,
};

/// Source baseline selected explicitly; no draft behavior changes modern defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerProfile {
    /// Strict RFC 9360 end-entity integrity with modern registrations.
    Rfc9360,
    /// ISO/IEC 18013-5:2021 compatibility, including unprotected chains.
    Iso2021,
    /// Hash-pinned edition-2 DIS snapshot documented in the profile matrix.
    IsoEdition2Dis,
}

/// Opaque content purpose. Payload grammar, negotiation and trust stay outside COSE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerPurpose {
    /// Generic signed content under strict RFC 9360 policy.
    Generic,
    /// Attached issuer MSO bytes, including their original tag-24 encoding.
    IssuerMso,
    /// Detached device authentication bytes.
    DeviceAuthentication,
    /// Detached single-request reader authentication bytes.
    ReaderAuthentication,
    /// Detached whole-request authentication bytes in caller-supplied order.
    ReaderAuthenticationAll,
    /// Attached signed MSO revocation list; schema and freshness are external.
    MsoRevocation,
    /// Optional VICAL attached container with unprotected x5chain.
    Vical,
    /// Informative RICAL attached container with protected x5chain.
    Rical,
}

/// Exact envelope acceptance, independently of payload attachment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopePolicy {
    /// Require the untagged four-element array.
    Untagged,
    /// Require tag 18 around the four-element array.
    Tagged,
    /// Explicitly allow either form for a generic container.
    Either,
}

/// Attached/detached content selection is never inferred from null or empty data.
pub enum ContainerContent<'a> {
    /// Use the exact attached byte-string payload.
    Attached,
    /// Require null on the wire and authenticate these exact external bytes.
    Detached(&'a [u8]),
}

/// Explicit per-call contract. There are deliberately no permissive defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerPolicy {
    /// Source baseline.
    pub profile: ContainerProfile,
    /// Distinct application purpose.
    pub purpose: ContainerPurpose,
    /// Exact accepted envelope form.
    pub envelope: EnvelopePolicy,
}

impl ContainerPolicy {
    pub(super) fn check(
        self,
        suite: SignatureSuite,
        attached: bool,
        tagged: bool,
        aad: &[u8],
    ) -> Result<(), ContainerError> {
        if matches!(
            (self.envelope, tagged),
            (EnvelopePolicy::Untagged, true) | (EnvelopePolicy::Tagged, false)
        ) {
            return Err(Reason::Profile.into());
        }
        match (self.profile, suite.registration()) {
            (ContainerProfile::Rfc9360, SignatureRegistration::Modern(_))
                if self.purpose == ContainerPurpose::Generic =>
            {
                return Ok(())
            }
            (
                ContainerProfile::Iso2021 | ContainerProfile::IsoEdition2Dis,
                SignatureRegistration::Iso(_),
            ) => {}
            _ => return Err(Reason::Profile.into()),
        }
        if !aad.is_empty() || tagged || self.envelope != EnvelopePolicy::Untagged {
            return Err(Reason::Profile.into());
        }
        let needs_attached = matches!(
            self.purpose,
            ContainerPurpose::IssuerMso
                | ContainerPurpose::MsoRevocation
                | ContainerPurpose::Vical
                | ContainerPurpose::Rical
        );
        if self.purpose == ContainerPurpose::Generic || attached != needs_attached {
            return Err(Reason::Profile.into());
        }
        if self.profile == ContainerProfile::Iso2021
            && matches!(
                self.purpose,
                ContainerPurpose::ReaderAuthenticationAll
                    | ContainerPurpose::MsoRevocation
                    | ContainerPurpose::Rical
            )
        {
            return Err(Reason::Profile.into());
        }
        Ok(())
    }
}

/// Caller-tightenable resource ceilings. Hard crate ceilings still apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerLimits {
    /// Maximum encoded envelope bytes (hard maximum 65,536).
    pub encoded_bytes: usize,
    /// Maximum payload bytes (hard maximum 1,048,576).
    pub payload_bytes: usize,
    /// Maximum external AAD bytes (hard maximum 65,536).
    pub external_aad_bytes: usize,
}

impl Default for ContainerLimits {
    fn default() -> Self {
        Self {
            encoded_bytes: crate::limits::MAX_COSE_SIGN1_BYTES,
            payload_bytes: crate::limits::MAX_DETACHED_PAYLOAD_BYTES,
            external_aad_bytes: crate::limits::MAX_COSE_SIGN1_BYTES,
        }
    }
}
