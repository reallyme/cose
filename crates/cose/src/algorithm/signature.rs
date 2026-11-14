// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact COSE signature algorithm registrations.

use coset::{iana, iana::EnumI64, RegisteredLabelWithPrivate};
use reallyme_crypto::core::Algorithm;

use crate::CoseError;

/// Closed compatibility view generated from the protobuf selector.
pub use crate::generated_contract::CoseSignatureAlgorithm;

impl CoseSignatureAlgorithm {
    /// Return the cryptographic primitive used to execute this registration.
    ///
    /// # Errors
    /// Legacy registrations that require a curve return `UnsupportedAlgorithm`.
    pub fn crypto_algorithm(self) -> Result<Algorithm, CoseError> {
        Ok(match self {
            Self::Es384 | Self::Es512 | Self::EdDsa => return Err(CoseError::UnsupportedAlgorithm),
            Self::Ed25519 => Algorithm::Ed25519,
            Self::Es256 | Self::Esp256 => Algorithm::P256,
            Self::Esp384 => Algorithm::P384,
            Self::Esp512 => Algorithm::P521,
            Self::Es256K => Algorithm::Secp256k1,
            Self::MlDsa44 => Algorithm::MlDsa44,
            Self::MlDsa65 => Algorithm::MlDsa65,
            Self::MlDsa87 => Algorithm::MlDsa87,
        })
    }

    pub(crate) const fn from_crypto_algorithm(algorithm: Algorithm) -> Result<Self, CoseError> {
        match algorithm {
            Algorithm::Ed25519 => Ok(Self::Ed25519),
            Algorithm::P256 => Ok(Self::Esp256),
            Algorithm::P384 => Ok(Self::Esp384),
            Algorithm::P521 => Ok(Self::Esp512),
            Algorithm::Secp256k1 => Ok(Self::Es256K),
            Algorithm::MlDsa44 => Ok(Self::MlDsa44),
            Algorithm::MlDsa65 => Ok(Self::MlDsa65),
            Algorithm::MlDsa87 => Ok(Self::MlDsa87),
            Algorithm::X25519
            | Algorithm::MlKem512
            | Algorithm::MlKem768
            | Algorithm::MlKem1024
            | Algorithm::SlhDsaSha2_128s
            | Algorithm::XWing768 => Err(CoseError::UnsupportedAlgorithm),
        }
    }

    pub(crate) fn to_iana(self) -> Result<iana::Algorithm, CoseError> {
        iana::Algorithm::from_i64(self.identifier()).ok_or(CoseError::UnsupportedAlgorithm)
    }

    pub(crate) fn from_registered(
        algorithm: &RegisteredLabelWithPrivate<iana::Algorithm>,
    ) -> Result<Self, CoseError> {
        match algorithm {
            RegisteredLabelWithPrivate::Assigned(assigned) => Self::from_iana(*assigned),
            RegisteredLabelWithPrivate::PrivateUse(identifier) => {
                Self::from_identifier(*identifier).and_then(|value| {
                    value.crypto_algorithm()?;
                    Ok(value)
                })
            }
            RegisteredLabelWithPrivate::Text(_) => Err(CoseError::UnsupportedAlgorithm),
        }
    }

    pub(crate) fn from_iana(algorithm: iana::Algorithm) -> Result<Self, CoseError> {
        let value = Self::from_identifier(algorithm.to_i64())?;
        value.crypto_algorithm()?;
        Ok(value)
    }
}
