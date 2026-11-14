// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseContainerPurpose as Wire;

/// Closed native view of the authoritative CoseContainerPurpose selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ContainerPurpose {
    /// Schema selector 1.
    Generic,
    /// Schema selector 2.
    IssuerMso,
    /// Schema selector 3.
    DeviceAuthentication,
    /// Schema selector 4.
    ReaderAuthentication,
    /// Schema selector 5.
    ReaderAuthenticationAll,
    /// Schema selector 6.
    MsoRevocation,
    /// Schema selector 7.
    Vical,
    /// Schema selector 8.
    Rical,
}

impl TryFrom<EnumValue<Wire>> for ContainerPurpose {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::Generic) => Ok(Self::Generic),
            Some(Wire::IssuerMso) => Ok(Self::IssuerMso),
            Some(Wire::DeviceAuthentication) => Ok(Self::DeviceAuthentication),
            Some(Wire::ReaderAuthentication) => Ok(Self::ReaderAuthentication),
            Some(Wire::ReaderAuthenticationAll) => Ok(Self::ReaderAuthenticationAll),
            Some(Wire::MsoRevocation) => Ok(Self::MsoRevocation),
            Some(Wire::Vical) => Ok(Self::Vical),
            Some(Wire::Rical) => Ok(Self::Rical),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<ContainerPurpose> for Wire {
    fn from(value: ContainerPurpose) -> Self {
        match value {
            ContainerPurpose::Generic => Self::Generic,
            ContainerPurpose::IssuerMso => Self::IssuerMso,
            ContainerPurpose::DeviceAuthentication => Self::DeviceAuthentication,
            ContainerPurpose::ReaderAuthentication => Self::ReaderAuthentication,
            ContainerPurpose::ReaderAuthenticationAll => Self::ReaderAuthenticationAll,
            ContainerPurpose::MsoRevocation => Self::MsoRevocation,
            ContainerPurpose::Vical => Self::Vical,
            ContainerPurpose::Rical => Self::Rical,
        }
    }
}

impl ContainerPurpose {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[
        Self::Generic,
        Self::IssuerMso,
        Self::DeviceAuthentication,
        Self::ReaderAuthentication,
        Self::ReaderAuthenticationAll,
        Self::MsoRevocation,
        Self::Vical,
        Self::Rical,
    ];
}
