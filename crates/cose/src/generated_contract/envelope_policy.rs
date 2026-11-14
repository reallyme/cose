// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseEnvelopePolicy as Wire;

/// Closed native view of the authoritative CoseEnvelopePolicy selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EnvelopePolicy {
    /// Schema selector 1.
    Untagged,
    /// Schema selector 2.
    Tagged,
    /// Schema selector 3.
    Either,
}

impl TryFrom<EnumValue<Wire>> for EnvelopePolicy {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::Untagged) => Ok(Self::Untagged),
            Some(Wire::Tagged) => Ok(Self::Tagged),
            Some(Wire::Either) => Ok(Self::Either),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<EnvelopePolicy> for Wire {
    fn from(value: EnvelopePolicy) -> Self {
        match value {
            EnvelopePolicy::Untagged => Self::Untagged,
            EnvelopePolicy::Tagged => Self::Tagged,
            EnvelopePolicy::Either => Self::Either,
        }
    }
}

impl EnvelopePolicy {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[Self::Untagged, Self::Tagged, Self::Either];
}
