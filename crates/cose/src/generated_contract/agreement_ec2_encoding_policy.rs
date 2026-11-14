// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseAgreementEc2EncodingPolicy as Wire;

/// Closed native view of the authoritative CoseAgreementEc2EncodingPolicy selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AgreementEc2EncodingPolicy {
    /// Schema selector 1.
    FullCoordinatesOnly,
    /// Schema selector 2.
    FullOrCompressed,
}

impl TryFrom<EnumValue<Wire>> for AgreementEc2EncodingPolicy {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::FullCoordinatesOnly) => Ok(Self::FullCoordinatesOnly),
            Some(Wire::FullOrCompressed) => Ok(Self::FullOrCompressed),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<AgreementEc2EncodingPolicy> for Wire {
    fn from(value: AgreementEc2EncodingPolicy) -> Self {
        match value {
            AgreementEc2EncodingPolicy::FullCoordinatesOnly => Self::FullCoordinatesOnly,
            AgreementEc2EncodingPolicy::FullOrCompressed => Self::FullOrCompressed,
        }
    }
}

impl AgreementEc2EncodingPolicy {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[Self::FullCoordinatesOnly, Self::FullOrCompressed];
}
