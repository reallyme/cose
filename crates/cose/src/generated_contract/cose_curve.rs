// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseNamedCurve as Wire;

/// Closed native view of the authoritative CoseNamedCurve selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoseCurve {
    /// Schema selector 1.
    P256,
    /// Schema selector 2.
    P384,
    /// Schema selector 3.
    P521,
    /// Schema selector 4.
    X25519,
    /// Schema selector 5.
    X448,
    /// Schema selector 6.
    Ed25519,
    /// Schema selector 7.
    Ed448,
    /// Schema selector 8.
    Secp256k1,
    /// Schema selector 256.
    BrainpoolP256r1,
    /// Schema selector 257.
    BrainpoolP320r1,
    /// Schema selector 258.
    BrainpoolP384r1,
    /// Schema selector 259.
    BrainpoolP512r1,
}

impl TryFrom<EnumValue<Wire>> for CoseCurve {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::P256) => Ok(Self::P256),
            Some(Wire::P384) => Ok(Self::P384),
            Some(Wire::P521) => Ok(Self::P521),
            Some(Wire::X25519) => Ok(Self::X25519),
            Some(Wire::X448) => Ok(Self::X448),
            Some(Wire::Ed25519) => Ok(Self::Ed25519),
            Some(Wire::Ed448) => Ok(Self::Ed448),
            Some(Wire::Secp256k1) => Ok(Self::Secp256k1),
            Some(Wire::BrainpoolP256r1) => Ok(Self::BrainpoolP256r1),
            Some(Wire::BrainpoolP320r1) => Ok(Self::BrainpoolP320r1),
            Some(Wire::BrainpoolP384r1) => Ok(Self::BrainpoolP384r1),
            Some(Wire::BrainpoolP512r1) => Ok(Self::BrainpoolP512r1),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<CoseCurve> for Wire {
    fn from(value: CoseCurve) -> Self {
        match value {
            CoseCurve::P256 => Self::P256,
            CoseCurve::P384 => Self::P384,
            CoseCurve::P521 => Self::P521,
            CoseCurve::X25519 => Self::X25519,
            CoseCurve::X448 => Self::X448,
            CoseCurve::Ed25519 => Self::Ed25519,
            CoseCurve::Ed448 => Self::Ed448,
            CoseCurve::Secp256k1 => Self::Secp256k1,
            CoseCurve::BrainpoolP256r1 => Self::BrainpoolP256r1,
            CoseCurve::BrainpoolP320r1 => Self::BrainpoolP320r1,
            CoseCurve::BrainpoolP384r1 => Self::BrainpoolP384r1,
            CoseCurve::BrainpoolP512r1 => Self::BrainpoolP512r1,
        }
    }
}

impl CoseCurve {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[
        Self::P256,
        Self::P384,
        Self::P521,
        Self::X25519,
        Self::X448,
        Self::Ed25519,
        Self::Ed448,
        Self::Secp256k1,
        Self::BrainpoolP256r1,
        Self::BrainpoolP320r1,
        Self::BrainpoolP384r1,
        Self::BrainpoolP512r1,
    ];
}

impl CoseCurve {
    /// Exact COSE wire registration declared by the schema.
    #[must_use]
    pub const fn identifier(self) -> i64 {
        match self {
            Self::P256 => 1,
            Self::P384 => 2,
            Self::P521 => 3,
            Self::X25519 => 4,
            Self::X448 => 5,
            Self::Ed25519 => 6,
            Self::Ed448 => 7,
            Self::Secp256k1 => 8,
            Self::BrainpoolP256r1 => 256,
            Self::BrainpoolP320r1 => 257,
            Self::BrainpoolP384r1 => 258,
            Self::BrainpoolP512r1 => 259,
        }
    }
    /// Resolve an exact wire identity without profile or provider substitution.
    ///
    /// # Errors
    /// Returns UnsupportedAlgorithm for an unregistered or unsupported identity.
    pub fn from_identifier(identifier: i64) -> Result<Self, CoseError> {
        match identifier {
            1 => Ok(Self::P256),
            2 => Ok(Self::P384),
            3 => Ok(Self::P521),
            4 => Ok(Self::X25519),
            5 => Ok(Self::X448),
            6 => Ok(Self::Ed25519),
            7 => Ok(Self::Ed448),
            8 => Ok(Self::Secp256k1),
            256 => Ok(Self::BrainpoolP256r1),
            257 => Ok(Self::BrainpoolP320r1),
            258 => Ok(Self::BrainpoolP384r1),
            259 => Ok(Self::BrainpoolP512r1),
            _ => Err(CoseError::UnsupportedAlgorithm),
        }
    }
}
