// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CosePointEncoding as Wire;

/// Closed native view of the authoritative CosePointEncoding selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CosePointEncoding {
    /// Schema selector 1.
    Ec2Coordinates,
    /// Schema selector 2.
    Ec2YSign,
    /// Schema selector 3.
    Okp,
}

impl TryFrom<EnumValue<Wire>> for CosePointEncoding {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::Ec2Coordinates) => Ok(Self::Ec2Coordinates),
            Some(Wire::Ec2YSign) => Ok(Self::Ec2YSign),
            Some(Wire::Okp) => Ok(Self::Okp),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<CosePointEncoding> for Wire {
    fn from(value: CosePointEncoding) -> Self {
        match value {
            CosePointEncoding::Ec2Coordinates => Self::Ec2Coordinates,
            CosePointEncoding::Ec2YSign => Self::Ec2YSign,
            CosePointEncoding::Okp => Self::Okp,
        }
    }
}

impl CosePointEncoding {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[Self::Ec2Coordinates, Self::Ec2YSign, Self::Okp];
}

#[allow(non_upper_case_globals)]
impl CosePointEncoding {
    /// Compatibility spelling for the canonical point representation.
    pub const FullCoordinates: Self = Self::Ec2Coordinates;
    /// Compatibility spelling for the canonical point representation.
    pub const Compressed: Self = Self::Ec2YSign;
}

impl
    TryFrom<
        buffa::EnumValue<
            reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseEc2PointEncoding,
        >,
    > for CosePointEncoding
{
    type Error = crate::CoseError;
    fn try_from(
        value: buffa::EnumValue<
            reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseEc2PointEncoding,
        >,
    ) -> Result<Self, Self::Error> {
        use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseEc2PointEncoding as Legacy;
        match value.as_known() {
            Some(Legacy::Compressed) => Ok(Self::Ec2YSign),
            Some(Legacy::FullCoordinates) => Ok(Self::Ec2Coordinates),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}
