// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ContainerError, ContainerErrorReason as Reason, SignatureSuite};

/// Closed compatibility view generated from the protobuf selector.
pub use crate::generated_contract::ContainerProfile;

/// Closed compatibility view generated from the protobuf selector.
pub use crate::generated_contract::ContainerPurpose;

/// Closed compatibility view generated from the protobuf selector.
pub use crate::generated_contract::EnvelopePolicy;

/// Attached/detached content selection is never inferred from null or empty data.
pub use crate::generated_contract::ContainerContent;

/// Closed native view generated from the authoritative message.
pub use crate::generated_contract::ContainerPolicy;

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
        // A generated suite is a value projection, not authorization. Recheck
        // its tuple so generated values and retained constructors obey the same
        // selected profile, without changing the existing profile-error order.
        match self.profile {
            ContainerProfile::Rfc9360
                if !suite.registration().is_iso() && self.purpose == ContainerPurpose::Generic =>
            {
                if SignatureSuite::modern(suite.registration())? != suite {
                    return Err(Reason::KeyAlgorithmMismatch.into());
                }
                return Ok(());
            }
            ContainerProfile::Iso2021 | ContainerProfile::IsoEdition2Dis
                if suite.registration().is_iso() =>
            {
                SignatureSuite::iso(suite.registration(), suite.curve())?;
            }
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

/// Compatibility name for the generated checked byte-limit view.
pub use crate::generated_contract::ContainerLimits;
