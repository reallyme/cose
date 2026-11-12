// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{CertificateHeaders, ContainerError, SignatureSuite};
use crate::iso18013::{Iso18013CryptoVerifier, Iso18013Verifier};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Stable validated public-key capability supplied by the application boundary.
///
/// Implementations must validate named-curve points, subgroup/usage restrictions
/// and effective certificate algorithm parameters before exposing a capability.
/// All three identity methods must remain stable. `verify` consumes the entire
/// message with the suite's ECDSA hash or pure EdDSA (empty context), never a
/// caller-prehashed message. Platform adapters route crypto through reallyme-crypto.
pub trait VerificationKey {
    /// Exact wire registration and validated named curve.
    fn suite(&self) -> SignatureSuite;
    /// Validated SEC1 or OKP public encoding, with no private key material.
    fn public_key(&self) -> &[u8];
    /// Application-defined fixed context binding, e.g. a validated path/policy ID.
    fn context_id(&self) -> &[u8; 32];
    /// Verify the full Sig_structure and strict COSE signature.
    ///
    /// # Errors
    /// Returns fixed provider, key, backend, or authentication failures.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), ContainerError>;
}

/// Published reallyme-crypto adapter for its supported NIST/Ed25519 pairs.
pub struct CryptoVerificationKey {
    suite: SignatureSuite,
    context: Zeroizing<[u8; 32]>,
    verifier: Iso18013CryptoVerifier,
}

impl CryptoVerificationKey {
    /// Validate and bind an owned public key; unsupported providers fail closed.
    ///
    /// # Errors
    /// Returns fixed key, provider, or allocation failures.
    pub fn new(
        suite: SignatureSuite,
        public_key: Zeroizing<Vec<u8>>,
        context_id: [u8; 32],
    ) -> Result<Self, ContainerError> {
        let verifier = Iso18013CryptoVerifier::new(suite.primitive_suite()?, public_key)?;
        Ok(Self {
            suite,
            context: Zeroizing::new(context_id),
            verifier,
        })
    }
}

impl VerificationKey for CryptoVerificationKey {
    fn suite(&self) -> SignatureSuite {
        self.suite
    }
    fn public_key(&self) -> &[u8] {
        self.verifier.public_key()
    }
    fn context_id(&self) -> &[u8; 32] {
        &self.context
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), ContainerError> {
        let algorithm = self.verifier.suite().crypto_algorithm()?;
        let backend = if self.suite.curve().coordinate_length().is_some() {
            super::cose_signature_to_der(self.suite.curve(), signature)?
        } else {
            super::validate_cose_signature(self.suite.curve(), signature)?;
            super::own_bytes::copy(signature)?
        };
        reallyme_crypto::dispatch::verify(algorithm, self.verifier.public_key(), message, &backend)
            .map_err(crate::error::verify_error_from_algorithm_error)
            .map_err(Into::into)
    }
}
impl ZeroizeOnDrop for CryptoVerificationKey {}

/// Effective key and exact selected end-entity DER from certificate validation.
///
/// This value is supplied only after the external certificate boundary applies
/// its chosen generic mdoc or mDL-specific path, usage and authority policy.
pub struct CertificateSelection<'a> {
    /// The effective validated working key and parameters, not a header-selected key.
    pub key: &'a dyn VerificationKey,
    /// Exact DER certificate actually selected by that boundary.
    pub end_entity_der: &'a [u8],
}

/// Injected certificate-validation boundary; no discovery, networking or X.509 policy here.
pub trait CertificateValidator {
    /// Resolve the effective working key and end entity under external policy.
    ///
    /// `headers` is untrusted discovery data. `algorithm` is the exact protected
    /// registration; the implementation must not authorize it merely because a
    /// certificate or kid occurs in the envelope.
    ///
    /// # Errors
    /// Return fixed certificate-validation/provider failures, without backend text.
    fn resolve(
        &self,
        headers: &CertificateHeaders<'_>,
        algorithm: i64,
    ) -> Result<CertificateSelection<'_>, ContainerError>;
}

/// Explicit key source, preventing an included certificate from replacing a key.
pub enum VerificationSource<'a> {
    /// A separately validated public key; certificate headers must be absent.
    Key(&'a dyn VerificationKey),
    /// Certificate policy returning the actual effective key and selected DER.
    Certificates(&'a dyn CertificateValidator),
}
