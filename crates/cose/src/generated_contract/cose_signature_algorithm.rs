// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseSignatureAlgorithm as Wire;

/// Closed native view of the authoritative CoseSignatureAlgorithm selector.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoseSignatureAlgorithm {
    /// Schema selector 100.
    Ed25519,
    /// Schema selector 201.
    Es256,
    /// Schema selector 212.
    Es384,
    /// Schema selector 222.
    Es512,
    /// Schema selector 101.
    EdDsa,
    /// Schema selector 202.
    Esp256,
    /// Schema selector 211.
    Esp384,
    /// Schema selector 221.
    Esp512,
    /// Schema selector 230.
    Es256K,
    /// Schema selector 300.
    Ps256,
    /// Schema selector 301.
    Ps384,
    /// Schema selector 302.
    Ps512,
    /// Schema selector 310.
    Rs256,
    /// Schema selector 311.
    Rs384,
    /// Schema selector 312.
    Rs512,
    /// Schema selector 1000.
    MlDsa44,
    /// Schema selector 1010.
    MlDsa65,
    /// Schema selector 1020.
    MlDsa87,
}

#[allow(deprecated)]
impl TryFrom<EnumValue<Wire>> for CoseSignatureAlgorithm {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::Ed25519) => Ok(Self::Ed25519),
            Some(Wire::Es256) => Ok(Self::Es256),
            Some(Wire::Es384) => Ok(Self::Es384),
            Some(Wire::Es512) => Ok(Self::Es512),
            Some(Wire::Eddsa) => Ok(Self::EdDsa),
            Some(Wire::Esp256) => Ok(Self::Esp256),
            Some(Wire::Esp384) => Ok(Self::Esp384),
            Some(Wire::Esp512) => Ok(Self::Esp512),
            Some(Wire::EcdsaSecp256k1Sha256) => Ok(Self::Es256K),
            Some(Wire::Ps256) => Ok(Self::Ps256),
            Some(Wire::Ps384) => Ok(Self::Ps384),
            Some(Wire::Ps512) => Ok(Self::Ps512),
            Some(Wire::Rs256) => Ok(Self::Rs256),
            Some(Wire::Rs384) => Ok(Self::Rs384),
            Some(Wire::Rs512) => Ok(Self::Rs512),
            Some(Wire::MlDsa44) => Ok(Self::MlDsa44),
            Some(Wire::MlDsa65) => Ok(Self::MlDsa65),
            Some(Wire::MlDsa87) => Ok(Self::MlDsa87),
            Some(Wire::EcdsaP256Sha256) => Ok(Self::Esp256),
            Some(Wire::EcdsaP384Sha384) => Ok(Self::Esp384),
            Some(Wire::EcdsaP521Sha512) => Ok(Self::Esp512),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<CoseSignatureAlgorithm> for Wire {
    fn from(value: CoseSignatureAlgorithm) -> Self {
        match value {
            CoseSignatureAlgorithm::Ed25519 => Self::Ed25519,
            CoseSignatureAlgorithm::Es256 => Self::Es256,
            CoseSignatureAlgorithm::Es384 => Self::Es384,
            CoseSignatureAlgorithm::Es512 => Self::Es512,
            CoseSignatureAlgorithm::EdDsa => Self::Eddsa,
            CoseSignatureAlgorithm::Esp256 => Self::Esp256,
            CoseSignatureAlgorithm::Esp384 => Self::Esp384,
            CoseSignatureAlgorithm::Esp512 => Self::Esp512,
            CoseSignatureAlgorithm::Es256K => Self::EcdsaSecp256k1Sha256,
            CoseSignatureAlgorithm::Ps256 => Self::Ps256,
            CoseSignatureAlgorithm::Ps384 => Self::Ps384,
            CoseSignatureAlgorithm::Ps512 => Self::Ps512,
            CoseSignatureAlgorithm::Rs256 => Self::Rs256,
            CoseSignatureAlgorithm::Rs384 => Self::Rs384,
            CoseSignatureAlgorithm::Rs512 => Self::Rs512,
            CoseSignatureAlgorithm::MlDsa44 => Self::MlDsa44,
            CoseSignatureAlgorithm::MlDsa65 => Self::MlDsa65,
            CoseSignatureAlgorithm::MlDsa87 => Self::MlDsa87,
        }
    }
}

impl CoseSignatureAlgorithm {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[
        Self::Ed25519,
        Self::Es256,
        Self::Es384,
        Self::Es512,
        Self::EdDsa,
        Self::Esp256,
        Self::Esp384,
        Self::Esp512,
        Self::Es256K,
        Self::Ps256,
        Self::Ps384,
        Self::Ps512,
        Self::Rs256,
        Self::Rs384,
        Self::Rs512,
        Self::MlDsa44,
        Self::MlDsa65,
        Self::MlDsa87,
    ];
}

impl CoseSignatureAlgorithm {
    /// Exact COSE wire registration declared by the schema.
    #[must_use]
    pub const fn identifier(self) -> i64 {
        match self {
            Self::Ed25519 => -19,
            Self::Es256 => -7,
            Self::Es384 => -35,
            Self::Es512 => -36,
            Self::EdDsa => -8,
            Self::Esp256 => -9,
            Self::Esp384 => -51,
            Self::Esp512 => -52,
            Self::Es256K => -47,
            Self::Ps256 => -37,
            Self::Ps384 => -38,
            Self::Ps512 => -39,
            Self::Rs256 => -257,
            Self::Rs384 => -258,
            Self::Rs512 => -259,
            Self::MlDsa44 => -48,
            Self::MlDsa65 => -49,
            Self::MlDsa87 => -50,
        }
    }
    /// Resolve an exact wire identity without profile or provider substitution.
    ///
    /// # Errors
    /// Returns UnsupportedAlgorithm for an unregistered or unsupported identity.
    pub fn from_identifier(identifier: i64) -> Result<Self, CoseError> {
        match identifier {
            -19 => Ok(Self::Ed25519),
            -7 => Ok(Self::Es256),
            -35 => Ok(Self::Es384),
            -36 => Ok(Self::Es512),
            -8 => Ok(Self::EdDsa),
            -9 => Ok(Self::Esp256),
            -51 => Ok(Self::Esp384),
            -52 => Ok(Self::Esp512),
            -47 => Ok(Self::Es256K),
            -37 => Ok(Self::Ps256),
            -38 => Ok(Self::Ps384),
            -39 => Ok(Self::Ps512),
            -257 => Ok(Self::Rs256),
            -258 => Ok(Self::Rs384),
            -259 => Ok(Self::Rs512),
            -48 => Ok(Self::MlDsa44),
            -49 => Ok(Self::MlDsa65),
            -50 => Ok(Self::MlDsa87),
            _ => Err(CoseError::UnsupportedAlgorithm),
        }
    }
}

impl CoseSignatureAlgorithm {
    /// Whether this is an original ISO suite registration. Entry points apply their explicit profile.
    #[must_use]
    pub const fn is_iso(self) -> bool {
        matches!(self, Self::Es256 | Self::Es384 | Self::Es512 | Self::EdDsa)
    }
    /// ECDSA message hash, independently of named key curve.
    #[cfg(feature = "cose-crypto")]
    #[must_use]
    pub const fn ecdsa_hash(self) -> Option<super::Iso18013EcdsaHash> {
        match self {
            Self::Es256 => Some(super::Iso18013EcdsaHash::Sha256),
            Self::Es384 => Some(super::Iso18013EcdsaHash::Sha384),
            Self::Es512 => Some(super::Iso18013EcdsaHash::Sha512),
            Self::Esp256 => Some(super::Iso18013EcdsaHash::Sha256),
            Self::Esp384 => Some(super::Iso18013EcdsaHash::Sha384),
            Self::Esp512 => Some(super::Iso18013EcdsaHash::Sha512),
            Self::Es256K => Some(super::Iso18013EcdsaHash::Sha256),
            _ => None,
        }
    }
}
