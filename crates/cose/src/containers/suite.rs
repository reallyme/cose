// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ContainerError, ContainerErrorReason as Reason};
use crate::iso18013::{
    Iso18013SignatureAlgorithm as Legacy, Iso18013SignatureCurve as Curve, Iso18013SignatureSuite,
};
use crate::CoseSignatureAlgorithm;

/// Exact signature registration; original and fully specified IDs never alias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureRegistration {
    /// Original registrations, available only through an explicit ISO profile.
    Iso(Legacy),
    /// Modern fully specified registration (ES256 is not accepted here).
    Modern(CoseSignatureAlgorithm),
}

impl SignatureRegistration {
    /// Exact received/emitted algorithm identifier.
    #[must_use]
    pub const fn identifier(self) -> i64 {
        match self {
            Self::Iso(alg) => alg.identifier(),
            Self::Modern(alg) => alg.identifier(),
        }
    }
}

/// A permitted named curve and exact registration, resolved together.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureSuite {
    registration: SignatureRegistration,
    curve: Curve,
}

impl SignatureSuite {
    /// Construct one of the ISO 2021 / pinned DIS algorithm-curve pairs.
    ///
    /// # Errors
    /// Returns `Algorithm` for combinations outside the ISO tables.
    pub fn iso(algorithm: Legacy, curve: Curve) -> Result<Self, ContainerError> {
        let permitted = matches!(
            (algorithm, curve),
            (Legacy::Es256, Curve::P256 | Curve::BrainpoolP256r1)
                | (
                    Legacy::Es384,
                    Curve::P384 | Curve::BrainpoolP320r1 | Curve::BrainpoolP384r1
                )
                | (Legacy::Es512, Curve::P521 | Curve::BrainpoolP512r1)
                | (Legacy::EdDsa, Curve::Ed25519 | Curve::Ed448)
        );
        if !permitted {
            return Err(Reason::Algorithm.into());
        }
        Ok(Self {
            registration: SignatureRegistration::Iso(algorithm),
            curve,
        })
    }

    /// Construct a fully specified modern suite for strict RFC 9360 use.
    ///
    /// # Errors
    /// Returns `Algorithm` for registrations outside this container surface.
    pub fn modern(algorithm: CoseSignatureAlgorithm) -> Result<Self, ContainerError> {
        let curve = match algorithm {
            CoseSignatureAlgorithm::Esp256 => Curve::P256,
            CoseSignatureAlgorithm::Esp384 => Curve::P384,
            CoseSignatureAlgorithm::Esp512 => Curve::P521,
            CoseSignatureAlgorithm::Ed25519 => Curve::Ed25519,
            _ => return Err(Reason::Algorithm.into()),
        };
        Ok(Self {
            registration: SignatureRegistration::Modern(algorithm),
            curve,
        })
    }

    /// Exact wire registration.
    #[must_use]
    pub const fn registration(self) -> SignatureRegistration {
        self.registration
    }
    /// Exact named verification curve.
    #[must_use]
    pub const fn curve(self) -> Curve {
        self.curve
    }
    pub(super) fn primitive_suite(self) -> Result<Iso18013SignatureSuite, ContainerError> {
        let algorithm = match self.registration {
            SignatureRegistration::Iso(algorithm) => algorithm,
            SignatureRegistration::Modern(CoseSignatureAlgorithm::Esp256) => Legacy::Es256,
            SignatureRegistration::Modern(CoseSignatureAlgorithm::Esp384) => Legacy::Es384,
            SignatureRegistration::Modern(CoseSignatureAlgorithm::Esp512) => Legacy::Es512,
            SignatureRegistration::Modern(CoseSignatureAlgorithm::Ed25519) => Legacy::EdDsa,
            _ => return Err(Reason::Algorithm.into()),
        };
        Iso18013SignatureSuite::new(algorithm, self.curve).map_err(Into::into)
    }
}
