// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseX5ChainHeaderPlacement as Wire;

/// Closed native view of the authoritative CoseX5ChainHeaderPlacement selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum X5ChainHeaderPlacement {
    /// Schema selector 1.
    Protected,
    /// Schema selector 2.
    Unprotected,
}

impl TryFrom<EnumValue<Wire>> for X5ChainHeaderPlacement {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::Protected) => Ok(Self::Protected),
            Some(Wire::Unprotected) => Ok(Self::Unprotected),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<X5ChainHeaderPlacement> for Wire {
    fn from(value: X5ChainHeaderPlacement) -> Self {
        match value {
            X5ChainHeaderPlacement::Protected => Self::Protected,
            X5ChainHeaderPlacement::Unprotected => Self::Unprotected,
        }
    }
}

impl X5ChainHeaderPlacement {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[Self::Protected, Self::Unprotected];
}
