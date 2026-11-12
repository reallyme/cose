// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::CoseError;

const P256_COORDINATE_BYTES: usize = 32;
const P384_COORDINATE_BYTES: usize = 48;
const P521_COORDINATE_BYTES: usize = 66;
const BRAINPOOL_P320_COORDINATE_BYTES: usize = 40;
const BRAINPOOL_P512_COORDINATE_BYTES: usize = 64;
const ED25519_PUBLIC_BYTES: usize = 32;
const ED448_PUBLIC_BYTES: usize = 57;

/// Named signature curves from the IANA COSE Elliptic Curves registry.
///
/// Agreement-only X25519 and X448 are deliberately excluded. Recognizing a
/// signature curve does not assert that the pinned crypto provider implements it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Iso18013SignatureCurve {
    /// NIST P-256, COSE curve 1.
    P256,
    /// NIST P-384, COSE curve 2.
    P384,
    /// NIST P-521, COSE curve 3.
    P521,
    /// Ed25519, COSE curve 6.
    Ed25519,
    /// Ed448, COSE curve 7.
    Ed448,
    /// brainpoolP256r1, COSE curve 256.
    BrainpoolP256r1,
    /// brainpoolP320r1, COSE curve 257.
    BrainpoolP320r1,
    /// brainpoolP384r1, COSE curve 258.
    BrainpoolP384r1,
    /// brainpoolP512r1, COSE curve 259.
    BrainpoolP512r1,
}

impl Iso18013SignatureCurve {
    /// Return the registered COSE curve identifier, never inferred from size.
    #[must_use]
    pub const fn identifier(self) -> i64 {
        match self {
            Self::P256 => 1,
            Self::P384 => 2,
            Self::P521 => 3,
            Self::Ed25519 => 6,
            Self::Ed448 => 7,
            Self::BrainpoolP256r1 => 256,
            Self::BrainpoolP320r1 => 257,
            Self::BrainpoolP384r1 => 258,
            Self::BrainpoolP512r1 => 259,
        }
    }

    /// Resolve a signature curve from its registered COSE identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CoseError::UnsupportedAlgorithm`] for unknown curves and for
    /// agreement-only curves, including X25519 and X448.
    pub fn from_identifier(identifier: i64) -> Result<Self, CoseError> {
        match identifier {
            1 => Ok(Self::P256),
            2 => Ok(Self::P384),
            3 => Ok(Self::P521),
            6 => Ok(Self::Ed25519),
            7 => Ok(Self::Ed448),
            256 => Ok(Self::BrainpoolP256r1),
            257 => Ok(Self::BrainpoolP320r1),
            258 => Ok(Self::BrainpoolP384r1),
            259 => Ok(Self::BrainpoolP512r1),
            _ => Err(CoseError::UnsupportedAlgorithm),
        }
    }

    pub(crate) const fn coordinate_length(self) -> Option<usize> {
        match self {
            Self::P256 | Self::BrainpoolP256r1 => Some(P256_COORDINATE_BYTES),
            Self::P384 | Self::BrainpoolP384r1 => Some(P384_COORDINATE_BYTES),
            Self::P521 => Some(P521_COORDINATE_BYTES),
            Self::BrainpoolP320r1 => Some(BRAINPOOL_P320_COORDINATE_BYTES),
            Self::BrainpoolP512r1 => Some(BRAINPOOL_P512_COORDINATE_BYTES),
            Self::Ed25519 | Self::Ed448 => None,
        }
    }

    pub(crate) const fn okp_public_length(self) -> Option<usize> {
        match self {
            Self::Ed25519 => Some(ED25519_PUBLIC_BYTES),
            Self::Ed448 => Some(ED448_PUBLIC_BYTES),
            _ => None,
        }
    }

    /// Return the exact raw COSE signature length for this named curve.
    ///
    /// # Errors
    ///
    /// Returns [`CoseError::ResourceLimitExceeded`] if width arithmetic overflows.
    pub fn signature_length(self) -> Result<usize, CoseError> {
        let width = self
            .coordinate_length()
            .or(self.okp_public_length())
            .ok_or(CoseError::UnsupportedAlgorithm)?;
        width.checked_mul(2).ok_or(CoseError::ResourceLimitExceeded)
    }
}
