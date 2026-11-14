// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseMlKemMode as Wire;

/// Closed native view of the authoritative CoseMlKemMode selector.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoseMlKemMode {
    /// Schema selector 1.
    Direct,
    /// Schema selector 2.
    KeyWrap,
}

impl TryFrom<EnumValue<Wire>> for CoseMlKemMode {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::Direct) => Ok(Self::Direct),
            Some(Wire::KeyWrap) => Ok(Self::KeyWrap),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<CoseMlKemMode> for Wire {
    fn from(value: CoseMlKemMode) -> Self {
        match value {
            CoseMlKemMode::Direct => Self::Direct,
            CoseMlKemMode::KeyWrap => Self::KeyWrap,
        }
    }
}

impl CoseMlKemMode {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[Self::Direct, Self::KeyWrap];
}
