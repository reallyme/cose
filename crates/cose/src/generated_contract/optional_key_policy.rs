// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseAgreementOptionalParameters as Wire;

/// Closed native view of the authoritative CoseAgreementOptionalParameters selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OptionalKeyPolicy {
    /// Schema selector 1.
    Cose,
    /// Schema selector 2.
    IsoPeer,
}

impl TryFrom<EnumValue<Wire>> for OptionalKeyPolicy {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::ValidateCose) => Ok(Self::Cose),
            Some(Wire::IgnoreIsoOptional) => Ok(Self::IsoPeer),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<OptionalKeyPolicy> for Wire {
    fn from(value: OptionalKeyPolicy) -> Self {
        match value {
            OptionalKeyPolicy::Cose => Self::ValidateCose,
            OptionalKeyPolicy::IsoPeer => Self::IgnoreIsoOptional,
        }
    }
}

impl OptionalKeyPolicy {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[Self::Cose, Self::IsoPeer];
}
