// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::CoseError;

/// ECDSA message hash selected by the original COSE registration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Iso18013EcdsaHash {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// Original RFC 8152 signature registrations used by the 2021 ISO profile.
///
/// These registrations do not determine a key curve. Resolve a
/// [`super::Iso18013SignatureSuite`] before choosing a cryptographic provider.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Iso18013SignatureAlgorithm {
    /// ECDSA with SHA-256 (`-7`).
    Es256,
    /// ECDSA with SHA-384 (`-35`).
    Es384,
    /// ECDSA with SHA-512 (`-36`).
    Es512,
    /// Pure EdDSA (`-8`), with its parameter set selected by the key curve.
    EdDsa,
}

impl Iso18013SignatureAlgorithm {
    /// Return the exact COSE wire identifier without modern substitution.
    #[must_use]
    pub const fn identifier(self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::Es384 => -35,
            Self::Es512 => -36,
            Self::EdDsa => -8,
        }
    }

    /// Resolve an original ISO-profile registration.
    ///
    /// # Errors
    ///
    /// Returns [`CoseError::UnsupportedAlgorithm`] for every other identifier,
    /// including ESP384, ESP512, and fully specified Ed25519.
    pub fn from_identifier(identifier: i64) -> Result<Self, CoseError> {
        match identifier {
            -7 => Ok(Self::Es256),
            -35 => Ok(Self::Es384),
            -36 => Ok(Self::Es512),
            -8 => Ok(Self::EdDsa),
            _ => Err(CoseError::UnsupportedAlgorithm),
        }
    }

    /// Return the ECDSA message hash, or `None` for pure EdDSA.
    #[must_use]
    pub const fn ecdsa_hash(self) -> Option<Iso18013EcdsaHash> {
        match self {
            Self::Es256 => Some(Iso18013EcdsaHash::Sha256),
            Self::Es384 => Some(Iso18013EcdsaHash::Sha384),
            Self::Es512 => Some(Iso18013EcdsaHash::Sha512),
            Self::EdDsa => None,
        }
    }
}
