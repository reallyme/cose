// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseEndEntityIntegrity as Wire;

/// Closed native view of the authoritative CoseEndEntityIntegrity selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EndEntityIntegrity {
    /// Schema selector 1.
    ExternalKey,
    /// Schema selector 2.
    ProtectedChain,
    /// Schema selector 3.
    ProtectedThumbprint,
    /// Schema selector 4.
    IsoUnprotectedChain,
}

impl TryFrom<EnumValue<Wire>> for EndEntityIntegrity {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::ExternalKey) => Ok(Self::ExternalKey),
            Some(Wire::ProtectedChain) => Ok(Self::ProtectedChain),
            Some(Wire::ProtectedThumbprint) => Ok(Self::ProtectedThumbprint),
            Some(Wire::IsoUnprotectedChain) => Ok(Self::IsoUnprotectedChain),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<EndEntityIntegrity> for Wire {
    fn from(value: EndEntityIntegrity) -> Self {
        match value {
            EndEntityIntegrity::ExternalKey => Self::ExternalKey,
            EndEntityIntegrity::ProtectedChain => Self::ProtectedChain,
            EndEntityIntegrity::ProtectedThumbprint => Self::ProtectedThumbprint,
            EndEntityIntegrity::IsoUnprotectedChain => Self::IsoUnprotectedChain,
        }
    }
}

impl EndEntityIntegrity {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[
        Self::ExternalKey,
        Self::ProtectedChain,
        Self::ProtectedThumbprint,
        Self::IsoUnprotectedChain,
    ];
}
