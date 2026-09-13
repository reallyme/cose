// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact COSE signature algorithm registrations.

use coset::{iana, RegisteredLabelWithPrivate};
use reallyme_crypto::core::Algorithm;

use crate::CoseError;

/// Exact signature algorithm identifier carried by a COSE header or COSE_Key.
///
/// This type is deliberately distinct from [`Algorithm`]. The crypto selector
/// identifies a primitive implementation, while COSE can register more than
/// one identifier for the same primitive. In particular, both ES256 (`-7`)
/// and ESP256 (`-9`) use the P-256/SHA-256 backend but remain distinct protocol
/// identities and must not be silently rewritten into one another.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoseSignatureAlgorithm {
    /// Fully specified Ed25519 (`-19`).
    Ed25519,
    /// ECDSA with SHA-256 (`-7`), restricted by this profile to P-256.
    Es256,
    /// Fully specified ECDSA with P-256 and SHA-256 (`-9`).
    Esp256,
    /// Fully specified ECDSA with P-384 and SHA-384 (`-51`).
    Esp384,
    /// Fully specified ECDSA with P-521 and SHA-512 (`-52`).
    Esp512,
    /// ECDSA with secp256k1 and SHA-256 (`-47`).
    Es256K,
    /// ML-DSA-44 (`-48`).
    MlDsa44,
    /// ML-DSA-65 (`-49`).
    MlDsa65,
    /// ML-DSA-87 (`-50`).
    MlDsa87,
}

impl CoseSignatureAlgorithm {
    /// Return the signed integer registered in the IANA COSE Algorithms table.
    #[must_use]
    pub const fn identifier(self) -> i64 {
        match self {
            Self::Ed25519 => -19,
            Self::Es256 => -7,
            Self::Esp256 => -9,
            Self::Esp384 => -51,
            Self::Esp512 => -52,
            Self::Es256K => -47,
            Self::MlDsa44 => -48,
            Self::MlDsa65 => -49,
            Self::MlDsa87 => -50,
        }
    }

    /// Return the cryptographic primitive used to execute this registration.
    #[must_use]
    pub const fn crypto_algorithm(self) -> Algorithm {
        match self {
            Self::Ed25519 => Algorithm::Ed25519,
            Self::Es256 | Self::Esp256 => Algorithm::P256,
            Self::Esp384 => Algorithm::P384,
            Self::Esp512 => Algorithm::P521,
            Self::Es256K => Algorithm::Secp256k1,
            Self::MlDsa44 => Algorithm::MlDsa44,
            Self::MlDsa65 => Algorithm::MlDsa65,
            Self::MlDsa87 => Algorithm::MlDsa87,
        }
    }

    /// Resolve a supported exact COSE signature identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CoseError::UnsupportedAlgorithm`] for identifiers outside the
    /// deliberately supported signature profile.
    pub fn from_identifier(identifier: i64) -> Result<Self, CoseError> {
        match identifier {
            -19 => Ok(Self::Ed25519),
            -7 => Ok(Self::Es256),
            -9 => Ok(Self::Esp256),
            -51 => Ok(Self::Esp384),
            -52 => Ok(Self::Esp512),
            -47 => Ok(Self::Es256K),
            -48 => Ok(Self::MlDsa44),
            -49 => Ok(Self::MlDsa65),
            -50 => Ok(Self::MlDsa87),
            _ => Err(CoseError::UnsupportedAlgorithm),
        }
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

    pub(crate) const fn to_iana(self) -> iana::Algorithm {
        match self {
            Self::Ed25519 => iana::Algorithm::Ed25519,
            Self::Es256 => iana::Algorithm::ES256,
            Self::Esp256 => iana::Algorithm::ESP256,
            Self::Esp384 => iana::Algorithm::ESP384,
            Self::Esp512 => iana::Algorithm::ESP512,
            Self::Es256K => iana::Algorithm::ES256K,
            Self::MlDsa44 => iana::Algorithm::ML_DSA_44,
            Self::MlDsa65 => iana::Algorithm::ML_DSA_65,
            Self::MlDsa87 => iana::Algorithm::ML_DSA_87,
        }
    }

    pub(crate) fn from_registered(
        algorithm: &RegisteredLabelWithPrivate<iana::Algorithm>,
    ) -> Result<Self, CoseError> {
        match algorithm {
            RegisteredLabelWithPrivate::Assigned(assigned) => Self::from_iana(*assigned),
            RegisteredLabelWithPrivate::PrivateUse(identifier) => {
                Self::from_identifier(*identifier)
            }
            RegisteredLabelWithPrivate::Text(_) => Err(CoseError::UnsupportedAlgorithm),
        }
    }

    pub(crate) const fn from_iana(algorithm: iana::Algorithm) -> Result<Self, CoseError> {
        match algorithm {
            iana::Algorithm::Ed25519 => Ok(Self::Ed25519),
            iana::Algorithm::ES256 => Ok(Self::Es256),
            iana::Algorithm::ESP256 => Ok(Self::Esp256),
            iana::Algorithm::ESP384 => Ok(Self::Esp384),
            iana::Algorithm::ESP512 => Ok(Self::Esp512),
            iana::Algorithm::ES256K => Ok(Self::Es256K),
            iana::Algorithm::ML_DSA_44 => Ok(Self::MlDsa44),
            iana::Algorithm::ML_DSA_65 => Ok(Self::MlDsa65),
            iana::Algorithm::ML_DSA_87 => Ok(Self::MlDsa87),
            _ => Err(CoseError::UnsupportedAlgorithm),
        }
    }
}
