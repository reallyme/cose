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

/// Closed view generated from the single curve selector.
pub use crate::generated_contract::CoseCurve as Iso18013SignatureCurve;

impl Iso18013SignatureCurve {
    pub(crate) const fn coordinate_length(self) -> Option<usize> {
        match self {
            Self::P256 | Self::BrainpoolP256r1 => Some(P256_COORDINATE_BYTES),
            Self::P384 | Self::BrainpoolP384r1 => Some(P384_COORDINATE_BYTES),
            Self::P521 => Some(P521_COORDINATE_BYTES),
            Self::BrainpoolP320r1 => Some(BRAINPOOL_P320_COORDINATE_BYTES),
            Self::BrainpoolP512r1 => Some(BRAINPOOL_P512_COORDINATE_BYTES),
            Self::Ed25519 | Self::Ed448 | Self::X25519 | Self::X448 => None,
            Self::Secp256k1 => Some(P256_COORDINATE_BYTES),
        }
    }

    pub(crate) const fn okp_public_length(self) -> Option<usize> {
        match self {
            Self::Ed25519 => Some(ED25519_PUBLIC_BYTES),
            Self::Ed448 => Some(ED448_PUBLIC_BYTES),
            Self::X25519 => Some(32),
            Self::X448 => Some(56),
            _ => None,
        }
    }

    /// Return the exact raw COSE signature length for this named curve.
    ///
    /// # Errors
    ///
    /// Returns [`CoseError::UnsupportedAlgorithm`] for a curve without a defined
    /// signature width, or [`CoseError::ResourceLimitExceeded`] if width
    /// arithmetic overflows.
    pub fn signature_length(self) -> Result<usize, CoseError> {
        if matches!(self, Self::X25519 | Self::X448) {
            return Err(CoseError::UnsupportedAlgorithm);
        }
        let width = self
            .coordinate_length()
            .or(self.okp_public_length())
            .ok_or(CoseError::UnsupportedAlgorithm)?;
        width.checked_mul(2).ok_or(CoseError::ResourceLimitExceeded)
    }
}
