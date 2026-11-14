// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed signing-provider boundary for non-exportable platform keys.

use reallyme_crypto::core::Algorithm;
use zeroize::Zeroizing;

use crate::algorithm::CoseSignatureAlgorithm;
use crate::CoseError;

/// Compatibility name for the shared schema-defined error owner.
pub type CoseSignerError = CoseError;

/// Provider for signing with an application-owned or non-exportable key.
///
/// The provider receives the complete COSE `Sig_structure` and returns the
/// native signature representation expected for [`Self::algorithm`]: DER for
/// NIST ECDSA algorithms and fixed-width bytes for the other supported
/// algorithms. The COSE layer checks its encoding and converts that result
/// before it is emitted. The provider remains responsible for signing with
/// the intended key; this boundary cannot authenticate a signature without
/// the corresponding public key.
pub trait CoseSigner {
    /// Algorithm bound to the provider's key handle.
    fn algorithm(&self) -> Algorithm;

    /// Exact COSE registration emitted for signatures from this provider.
    ///
    /// The default preserves the historical fully specified mappings. A
    /// provider that represents a WebAuthn-compatible P-256 key can override
    /// this method to return [`CoseSignatureAlgorithm::Es256`].
    ///
    /// # Errors
    ///
    /// Returns [`CoseSignerError::UnsupportedAlgorithm`] when the provider's
    /// crypto selector has no supported COSE signature registration.
    fn cose_algorithm(&self) -> Result<CoseSignatureAlgorithm, CoseSignerError> {
        CoseSignatureAlgorithm::from_crypto_algorithm(self.algorithm())
            .map_err(|_| CoseSignerError::UnsupportedAlgorithm)
    }

    /// Sign an exact COSE `Sig_structure` without exporting private key bytes.
    ///
    /// # Errors
    ///
    /// Returns a fixed [`CoseSignerError`] when the key, provider, algorithm,
    /// or backend cannot complete the operation.
    fn sign(&self, sig_structure: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoseSignerError>;
}
