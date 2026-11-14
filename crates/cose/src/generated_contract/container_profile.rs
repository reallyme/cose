// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseContainerProfile as Wire;

/// Closed native view of the authoritative CoseContainerProfile selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ContainerProfile {
    /// Schema selector 1.
    Rfc9360,
    /// Schema selector 2.
    Iso2021,
    /// Schema selector 3.
    IsoEdition2Dis,
}

impl TryFrom<EnumValue<Wire>> for ContainerProfile {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::Rfc9360) => Ok(Self::Rfc9360),
            Some(Wire::Iso2021) => Ok(Self::Iso2021),
            Some(Wire::IsoEdition2Dis) => Ok(Self::IsoEdition2Dis),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<ContainerProfile> for Wire {
    fn from(value: ContainerProfile) -> Self {
        match value {
            ContainerProfile::Rfc9360 => Self::Rfc9360,
            ContainerProfile::Iso2021 => Self::Iso2021,
            ContainerProfile::IsoEdition2Dis => Self::IsoEdition2Dis,
        }
    }
}

impl ContainerProfile {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[Self::Rfc9360, Self::Iso2021, Self::IsoEdition2Dis];
}
