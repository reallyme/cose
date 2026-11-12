// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ContainerError, ContainerErrorReason as Reason};
use crate::iso18013::Iso18013SignatureCurve;

const X25519_PUBLIC_BYTES: usize = 32;
const X448_PUBLIC_BYTES: usize = 56;

/// Exact named curve identity for the eleven ISO reader public-key mappings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerCurve {
    /// Signature-capable EC2 or Edwards curve (not necessarily signing usage).
    Named(Iso18013SignatureCurve),
    /// OKP X25519, COSE curve 4; agreement only.
    X25519,
    /// OKP X448, COSE curve 5; 56 bytes, agreement only.
    X448,
}

impl PeerCurve {
    /// Resolve a registered curve, never inferred from coordinate length.
    ///
    /// # Errors
    /// Returns `Algorithm` for unsupported curve IDs, including secp256k1 here.
    pub fn from_identifier(id: i64) -> Result<Self, ContainerError> {
        match id {
            4 => Ok(Self::X25519),
            5 => Ok(Self::X448),
            _ => Iso18013SignatureCurve::from_identifier(id)
                .map(Self::Named)
                .map_err(|_| Reason::Algorithm.into()),
        }
    }
    /// Registered COSE curve ID.
    #[must_use]
    pub const fn identifier(self) -> i64 {
        match self {
            Self::Named(curve) => curve.identifier(),
            Self::X25519 => 4,
            Self::X448 => 5,
        }
    }
    /// Named-curve EC2 coordinate width, or None for OKP.
    #[must_use]
    pub const fn coordinate_bytes(self) -> Option<usize> {
        match self {
            Self::Named(curve) => curve.coordinate_length(),
            Self::X25519 | Self::X448 => None,
        }
    }
    /// Exact OKP public width, distinguishing Ed448 (57) from X448 (56).
    #[must_use]
    pub const fn okp_bytes(self) -> Option<usize> {
        match self {
            Self::Named(curve) => curve.okp_public_length(),
            Self::X25519 => Some(X25519_PUBLIC_BYTES),
            Self::X448 => Some(X448_PUBLIC_BYTES),
        }
    }
}
