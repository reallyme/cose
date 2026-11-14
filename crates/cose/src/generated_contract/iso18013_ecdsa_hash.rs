// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseHashAlgorithm as Wire;

/// Closed native view of the authoritative CoseHashAlgorithm selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Iso18013EcdsaHash {
    /// Schema selector 100.
    Sha256,
    /// Schema selector 110.
    Sha384,
    /// Schema selector 120.
    Sha512,
}

impl TryFrom<EnumValue<Wire>> for Iso18013EcdsaHash {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::Sha256) => Ok(Self::Sha256),
            Some(Wire::Sha384) => Ok(Self::Sha384),
            Some(Wire::Sha512) => Ok(Self::Sha512),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<Iso18013EcdsaHash> for Wire {
    fn from(value: Iso18013EcdsaHash) -> Self {
        match value {
            Iso18013EcdsaHash::Sha256 => Self::Sha256,
            Iso18013EcdsaHash::Sha384 => Self::Sha384,
            Iso18013EcdsaHash::Sha512 => Self::Sha512,
        }
    }
}

impl Iso18013EcdsaHash {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[Self::Sha256, Self::Sha384, Self::Sha512];
}
