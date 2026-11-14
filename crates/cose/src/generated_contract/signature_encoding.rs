// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseSignatureEncoding as Wire;

/// Closed native view of the authoritative CoseSignatureEncoding selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SignatureEncoding {
    /// Schema selector 1.
    EcdsaFixed,
    /// Schema selector 2.
    EcdsaDer,
    /// Schema selector 3.
    EdDsa,
    /// Schema selector 4.
    CoseNative,
}

impl TryFrom<EnumValue<Wire>> for SignatureEncoding {
    type Error = CoseError;
    fn try_from(value: EnumValue<Wire>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Wire::CoseEcdsa) => Ok(Self::EcdsaFixed),
            Some(Wire::EcdsaDer) => Ok(Self::EcdsaDer),
            Some(Wire::Eddsa) => Ok(Self::EdDsa),
            Some(Wire::CoseNative) => Ok(Self::CoseNative),
            _ => Err(crate::error::CoseErrorReason::CommonInvalidParameter.into()),
        }
    }
}

impl From<SignatureEncoding> for Wire {
    fn from(value: SignatureEncoding) -> Self {
        match value {
            SignatureEncoding::EcdsaFixed => Self::CoseEcdsa,
            SignatureEncoding::EcdsaDer => Self::EcdsaDer,
            SignatureEncoding::EdDsa => Self::Eddsa,
            SignatureEncoding::CoseNative => Self::CoseNative,
        }
    }
}

impl SignatureEncoding {
    /// Complete closed selector set, generated from the schema.
    pub const ALL: &[Self] = &[
        Self::EcdsaFixed,
        Self::EcdsaDer,
        Self::EdDsa,
        Self::CoseNative,
    ];
}
