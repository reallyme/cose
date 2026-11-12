// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::Algorithm;

use crate::CoseError;

use super::{Iso18013SignatureAlgorithm, Iso18013SignatureCurve};

/// Exact wire registration and named key curve authorized as one policy tuple.
///
/// Construction checks signature-family compatibility, not provider coverage or
/// application acceptance. Only pairs explicitly listed by a caller can verify.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Iso18013SignatureSuite {
    algorithm: Iso18013SignatureAlgorithm,
    curve: Iso18013SignatureCurve,
}

impl Iso18013SignatureSuite {
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
        let is_ecdsa = algorithm.ecdsa_hash().is_some();
        if is_ecdsa != curve.coordinate_length().is_some() {
            return Err(CoseError::UnsupportedAlgorithm);
        }
        Ok(Self { algorithm, curve })
    }

    /// Return the exact legacy registration, independently of the key curve.
    #[must_use]
    pub const fn algorithm(self) -> Iso18013SignatureAlgorithm {
        self.algorithm
    }

    /// Return the exact named key curve.
    #[must_use]
    pub const fn curve(self) -> Iso18013SignatureCurve {
        self.curve
    }

    /// Check whether the pinned `reallyme-crypto` adapter implements this pair.
    #[must_use]
    pub fn has_builtin_provider(self) -> bool {
        self.crypto_algorithm().is_ok()
    }

    pub(crate) fn crypto_algorithm(self) -> Result<Algorithm, CoseError> {
        // The pinned primitive selectors bind these exact pairs. In particular,
        // dispatching from the legacy registration alone would choose the wrong
        // curve for other explicitly permitted pairs.
        match (self.algorithm, self.curve) {
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
