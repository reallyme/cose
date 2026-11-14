// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseMacAlgorithm as Wire;

/// Closed native view of the authoritative CoseMacAlgorithm selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoseMacAlgorithm {
    /// Schema selector 4.
    Hmac256_64,
    /// Schema selector 5.
    Hmac256_256,
    /// Schema selector 6.
    Hmac384_384,
    /// Schema selector 7.
    Hmac512_512,
}

impl TryFrom<EnumValue<Wire>> for CoseMacAlgorithm {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::Hmac25664) => Ok(Self::Hmac256_64),
            Some(Wire::Hmac256256) => Ok(Self::Hmac256_256),
            Some(Wire::Hmac384384) => Ok(Self::Hmac384_384),
            Some(Wire::Hmac512512) => Ok(Self::Hmac512_512),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<CoseMacAlgorithm> for Wire {
    fn from(value: CoseMacAlgorithm) -> Self {
        match value {
            CoseMacAlgorithm::Hmac256_64 => Self::Hmac25664,
            CoseMacAlgorithm::Hmac256_256 => Self::Hmac256256,
            CoseMacAlgorithm::Hmac384_384 => Self::Hmac384384,
            CoseMacAlgorithm::Hmac512_512 => Self::Hmac512512,
        }
    }
}

impl CoseMacAlgorithm {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[
        Self::Hmac256_64,
        Self::Hmac256_256,
        Self::Hmac384_384,
        Self::Hmac512_512,
    ];
}

impl CoseMacAlgorithm {
    /// Exact COSE wire registration declared by the schema.
    #[must_use]
    pub const fn identifier(self) -> i64 {
        match self {
            Self::Hmac256_64 => 4,
            Self::Hmac256_256 => 5,
            Self::Hmac384_384 => 6,
            Self::Hmac512_512 => 7,
        }
    }
    /// Resolve an exact wire identity without profile or provider substitution.
    ///
    /// # Errors
    /// Returns UnsupportedAlgorithm for an unregistered or unsupported identity.
    pub fn from_identifier(identifier: i64) -> Result<Self, CoseError> {
        match identifier {
            4 => Ok(Self::Hmac256_64),
            5 => Ok(Self::Hmac256_256),
            6 => Ok(Self::Hmac384_384),
            7 => Ok(Self::Hmac512_512),
            _ => Err(CoseError::UnsupportedAlgorithm),
        }
    }
}
