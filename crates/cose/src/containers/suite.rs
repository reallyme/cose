// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ContainerError, ContainerErrorReason as Reason};
use crate::iso18013::{Iso18013SignatureAlgorithm, Iso18013SignatureCurve};
use crate::iso18013::{
    Iso18013SignatureAlgorithm as Legacy, Iso18013SignatureCurve as Curve, Iso18013SignatureSuite,
};
use crate::{CoseError, CoseSignatureAlgorithm};
use reallyme_crypto::core::Algorithm;

/// Compatibility name for the single generated signature identity.
pub type SignatureRegistration = CoseSignatureAlgorithm;

/// Closed native view generated from the authoritative message.
pub use crate::generated_contract::SignatureSuite;

impl SignatureSuite {
    pub(crate) fn for_container(
        algorithm: CoseSignatureAlgorithm,
        curve: Curve,
    ) -> Result<Self, ContainerError> {
        if algorithm.is_iso() {
            return Self::iso(algorithm, curve);
        }
        let suite = Self::modern(algorithm)?;
        if suite.curve() != curve {
            return Err(Reason::KeyAlgorithmMismatch.into());
        }
        Ok(suite)
    }

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
            registration: algorithm,
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
            registration: algorithm,
            curve,
        })
    }

    /// Exact wire registration.
    #[must_use]
    pub const fn registration(self) -> CoseSignatureAlgorithm {
        self.registration
    }
    /// Exact named verification curve.
    #[must_use]
    pub const fn curve(self) -> Curve {
        self.curve
    }
    pub(crate) fn primitive_suite(self) -> Result<Iso18013SignatureSuite, ContainerError> {
        // Fully specified registrations must validate their named curve before
        // translating to the crypto facade's primitive. Otherwise a missing
        // provider can conceal an invalid registration/curve binding.
        if !self.registration.is_iso() && Self::modern(self.registration)? != self {
            return Err(Reason::KeyAlgorithmMismatch.into());
        }
        let algorithm = match self.registration {
            alg if alg.is_iso() => alg,
            CoseSignatureAlgorithm::Esp256 => Legacy::Es256,
            CoseSignatureAlgorithm::Esp384 => Legacy::Es384,
            CoseSignatureAlgorithm::Esp512 => Legacy::Es512,
            CoseSignatureAlgorithm::Ed25519 => Legacy::EdDsa,
            _ => return Err(Reason::Algorithm.into()),
        };
        Iso18013SignatureSuite::new(algorithm, self.curve)
    }
}

impl SignatureSuite {
    /// Resolve a registration together with a named key curve.
    ///
    /// # Errors
    ///
    /// Returns [`CoseError::UnsupportedAlgorithm`] for an ECDSA/Edwards or
    /// EdDSA/Weierstrass mismatch. Missing providers remain a separate failure.
    pub fn new(
        algorithm: Iso18013SignatureAlgorithm,
        curve: Iso18013SignatureCurve,
    ) -> Result<Self, CoseError> {
        if !algorithm.is_iso() || matches!(curve, Curve::X25519 | Curve::X448 | Curve::Secp256k1) {
            return Err(crate::CoseError::UnsupportedAlgorithm);
        }
        let is_ecdsa = algorithm.ecdsa_hash().is_some();
        if is_ecdsa != curve.coordinate_length().is_some() {
            return Err(CoseError::UnsupportedAlgorithm);
        }
        Ok(Self {
            registration: algorithm,
            curve,
        })
    }

    /// Return the exact legacy registration, independently of the key curve.
    #[must_use]
    pub const fn algorithm(self) -> Iso18013SignatureAlgorithm {
        self.registration
    }

    /// Check whether the pinned `reallyme-crypto` adapter implements this pair.
    #[must_use]
    pub fn has_builtin_provider(self) -> bool {
        self.primitive_suite()
            .and_then(|suite| suite.crypto_algorithm())
            .is_ok()
    }

    pub(crate) fn crypto_algorithm(self) -> Result<Algorithm, CoseError> {
        // The pinned primitive selectors bind these exact pairs. In particular,
        // dispatching from the legacy registration alone would choose the wrong
        // curve for other explicitly permitted pairs.
        match (self.registration, self.curve) {
            (Iso18013SignatureAlgorithm::Es256, Iso18013SignatureCurve::P256) => {
                Ok(Algorithm::P256)
            }
            (Iso18013SignatureAlgorithm::Es384, Iso18013SignatureCurve::P384) => {
                Ok(Algorithm::P384)
            }
            (Iso18013SignatureAlgorithm::Es512, Iso18013SignatureCurve::P521) => {
                Ok(Algorithm::P521)
            }
            (Iso18013SignatureAlgorithm::EdDsa, Iso18013SignatureCurve::Ed25519) => {
                Ok(Algorithm::Ed25519)
            }
            _ => Err(CoseError::ProviderUnavailable),
        }
    }
}
