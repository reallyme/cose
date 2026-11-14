// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseMlKemProfile as Wire;

/// Closed native view of the authoritative CoseMlKemProfile selector.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoseMlKemProfile {
    /// Schema selector 1.
    ReallyMeV1,
}

impl TryFrom<EnumValue<Wire>> for CoseMlKemProfile {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::ReallyMeV1) => Ok(Self::ReallyMeV1),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<CoseMlKemProfile> for Wire {
    fn from(value: CoseMlKemProfile) -> Self {
        match value {
            CoseMlKemProfile::ReallyMeV1 => Self::ReallyMeV1,
        }
    }
}

impl CoseMlKemProfile {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[Self::ReallyMeV1];
}
