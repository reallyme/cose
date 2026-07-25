// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Typed signing-provider boundary for non-exportable platform keys.

use reallyme_crypto::core::Algorithm;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::CoseError;

/// Stable failures returned by an application or platform signing provider.
///
/// Variants deliberately carry no backend text, key handle, payload, or other
/// dynamic context so they remain safe to propagate through audit-facing APIs.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CoseSignerError {
    /// The provider does not implement the requested signature algorithm.
    #[error("signing algorithm unsupported by provider")]
    UnsupportedAlgorithm,
    /// The provider rejected or could not resolve its configured key handle.
    #[error("signing key unavailable or invalid")]
    InvalidKey,
    /// The provider, hardware, or required user-presence mechanism is unavailable.
    #[error("signing provider unavailable")]
    Unavailable,
    /// Signing failed without caller-safe diagnostic detail.
    #[error("signing backend failure")]
    Backend,
}

impl From<CoseSignerError> for CoseError {
    fn from(error: CoseSignerError) -> Self {
        match error {
            CoseSignerError::UnsupportedAlgorithm => Self::UnsupportedAlgorithm,
            CoseSignerError::InvalidKey => Self::InvalidKeyMaterial,
            CoseSignerError::Unavailable => Self::ProviderUnavailable,
            CoseSignerError::Backend => Self::Crypto,
        }
    }
}

/// Provider for signing with an application-owned or non-exportable key.
///
/// The provider receives the complete COSE `Sig_structure` and returns the
/// native signature representation expected for [`Self::algorithm`]: DER for
/// NIST ECDSA algorithms and fixed-width bytes for the other supported
/// algorithms. The COSE layer validates and converts that result before it is
/// encoded, so providers do not implement COSE or CBOR semantics.
pub trait CoseSigner {
    /// Algorithm bound to the provider's key handle.
    fn algorithm(&self) -> Algorithm;

    /// Sign an exact COSE `Sig_structure` without exporting private key bytes.
    ///
    /// # Errors
    ///
    /// Returns a fixed [`CoseSignerError`] when the key, provider, algorithm,
    /// or backend cannot complete the operation.
    fn sign(&self, sig_structure: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoseSignerError>;
}
