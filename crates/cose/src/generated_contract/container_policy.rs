// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use super::{ContainerProfile, ContainerPurpose, EnvelopePolicy};
use crate::CoseError;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseContainerPolicy as Wire;

/// Closed compatibility value generated from CoseContainerPolicy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContainerPolicy {
    /// Schema field profile.
    pub(crate) profile: ContainerProfile,
    /// Schema field purpose.
    pub(crate) purpose: ContainerPurpose,
    /// Schema field envelope.
    pub(crate) envelope: EnvelopePolicy,
}

impl TryFrom<&Wire> for ContainerPolicy {
    type Error = CoseError;
    fn try_from(value: &Wire) -> Result<Self, Self::Error> {
        Ok(Self {
            profile: ContainerProfile::try_from(value.profile)?,
            purpose: ContainerPurpose::try_from(value.purpose)?,
            envelope: EnvelopePolicy::try_from(value.envelope)?,
        })
    }
}

impl From<ContainerPolicy> for Wire {
    fn from(value: ContainerPolicy) -> Self {
        Self {profile: reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseContainerProfile::from(value.profile).into(),purpose: reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseContainerPurpose::from(value.purpose).into(),envelope: reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseEnvelopePolicy::from(value.envelope).into()}
    }
}
