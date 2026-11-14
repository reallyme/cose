// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseContentEncryptionAlgorithm as Wire;

/// Closed native view of the authoritative CoseContentEncryptionAlgorithm selector.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoseContentEncryptionAlgorithm {
    /// Schema selector 100.
    Aes128Gcm,
    /// Schema selector 110.
    Aes192Gcm,
    /// Schema selector 120.
    Aes256Gcm,
}

impl TryFrom<EnumValue<Wire>> for CoseContentEncryptionAlgorithm {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::Aes128Gcm) => Ok(Self::Aes128Gcm),
            Some(Wire::Aes192Gcm) => Ok(Self::Aes192Gcm),
            Some(Wire::Aes256Gcm) => Ok(Self::Aes256Gcm),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<CoseContentEncryptionAlgorithm> for Wire {
    fn from(value: CoseContentEncryptionAlgorithm) -> Self {
        match value {
            CoseContentEncryptionAlgorithm::Aes128Gcm => Self::Aes128Gcm,
            CoseContentEncryptionAlgorithm::Aes192Gcm => Self::Aes192Gcm,
            CoseContentEncryptionAlgorithm::Aes256Gcm => Self::Aes256Gcm,
        }
    }
}

impl CoseContentEncryptionAlgorithm {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[Self::Aes128Gcm, Self::Aes192Gcm, Self::Aes256Gcm];
}
