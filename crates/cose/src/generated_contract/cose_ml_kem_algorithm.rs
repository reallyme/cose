// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseKemAlgorithm as Wire;

/// Closed native view of the authoritative CoseKemAlgorithm selector.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoseMlKemAlgorithm {
    /// Schema selector 1000.
    MlKem512,
    /// Schema selector 1010.
    MlKem768,
    /// Schema selector 1020.
    MlKem1024,
}

impl TryFrom<EnumValue<Wire>> for CoseMlKemAlgorithm {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::MlKem512) => Ok(Self::MlKem512),
            Some(Wire::MlKem768) => Ok(Self::MlKem768),
            Some(Wire::MlKem1024) => Ok(Self::MlKem1024),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<CoseMlKemAlgorithm> for Wire {
    fn from(value: CoseMlKemAlgorithm) -> Self {
        match value {
            CoseMlKemAlgorithm::MlKem512 => Self::MlKem512,
            CoseMlKemAlgorithm::MlKem768 => Self::MlKem768,
            CoseMlKemAlgorithm::MlKem1024 => Self::MlKem1024,
        }
    }
}

impl CoseMlKemAlgorithm {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[Self::MlKem512, Self::MlKem768, Self::MlKem1024];
}
