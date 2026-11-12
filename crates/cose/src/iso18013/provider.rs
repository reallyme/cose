// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::verify_error_from_algorithm_error;
use crate::key::validate_public_key;
use crate::sign1::backend_signature_from_cose;
use crate::CoseError;

use super::Iso18013SignatureSuite;

const SEC1_PREFIX_BYTES: usize = 1;
const SEC1_COMPRESSED_EVEN: u8 = 2;
const SEC1_COMPRESSED_ODD: u8 = 3;
const SEC1_UNCOMPRESSED: u8 = 4;

/// Trusted verifier bound to a validated key and one exact algorithm/curve pair.
///
/// Providers must validate their key's named curve and any key-level algorithm
/// and usage restrictions before claiming a suite. They receive the complete
/// RFC 9052 Sig_structure and a raw, exact-width COSE signature. ECDSA providers
/// must use the suite's hash with the suite's curve; EdDSA must be pure, with
/// empty context. No provider may substitute modern wire registrations, try
/// alternate curves, or treat an unavailable provider as successful verification.
pub trait Iso18013Verifier {
    /// Exact registration and named curve bound to the validated verification key.
    /// This binding must remain stable for the verifier's lifetime.
    fn suite(&self) -> Iso18013SignatureSuite;

    /// Verify a raw COSE signature over the complete supplied Sig_structure.
    ///
    /// # Errors
    ///
    /// Returns fixed [`CoseError`] variants for invalid keys, failed signatures,
    /// unavailable providers, or backend failures, without diagnostic text.
    fn verify(&self, sig_structure: &[u8], signature: &[u8]) -> Result<(), CoseError>;
}

/// ISO verifier using the exact pairs implemented by the pinned crypto adapter.
///
/// Public keys can carry identifying material, so their owner wipes on drop
/// and cannot be cloned, serialized, or formatted.
pub struct Iso18013CryptoVerifier {
    suite: Iso18013SignatureSuite,
    public_key: Zeroizing<Vec<u8>>,
}

impl Iso18013CryptoVerifier {
    // The container adapter borrows this validated owner rather than retaining
    // a second identifying public-key buffer solely for receipt construction.
    pub(crate) fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Bind a supported suite to validated SEC1 or Ed25519 public key bytes.
    ///
    /// EC2 input must be compressed or uncompressed SEC1 for the named curve.
    /// Ed25519 input is its exact 32-byte compressed public encoding.
    ///
    /// # Errors
    ///
    /// Returns [`CoseError::ProviderUnavailable`] for unimplemented pairs and
    /// [`CoseError::InvalidKeyMaterial`] for invalid point or subgroup encodings.
    pub fn new(
        suite: Iso18013SignatureSuite,
        public_key: Zeroizing<Vec<u8>>,
    ) -> Result<Self, CoseError> {
        let algorithm = suite.crypto_algorithm()?;
        if let Some(width) = suite.curve().coordinate_length() {
            let compressed = width
                .checked_add(SEC1_PREFIX_BYTES)
                .ok_or(CoseError::ResourceLimitExceeded)?;
            let uncompressed = width
                .checked_mul(2)
                .and_then(|size| size.checked_add(SEC1_PREFIX_BYTES))
                .ok_or(CoseError::ResourceLimitExceeded)?;
            if !((public_key.len() == compressed
                && matches!(
                    public_key.first().copied(),
                    Some(SEC1_COMPRESSED_EVEN | SEC1_COMPRESSED_ODD)
                ))
                || (public_key.len() == uncompressed
                    && public_key.first() == Some(&SEC1_UNCOMPRESSED)))
            {
                return Err(CoseError::InvalidKeyMaterial);
            }
        }
        validate_public_key(algorithm, &public_key)?;
        Ok(Self { suite, public_key })
    }

    /// Import a bounded COSE public verification key with explicit suite binding.
    ///
    /// # Errors
    ///
    /// Returns [`CoseError`] for malformed or excessive encoding, wrong key
    /// type, curve, algorithm or key operations, private material, invalid
    /// points, or unavailable providers. The modern COSE_Key API is unchanged.
    pub fn from_cose_key(suite: Iso18013SignatureSuite, encoded: &[u8]) -> Result<Self, CoseError> {
        super::import_key::import(suite, encoded)
    }
}

impl Iso18013Verifier for Iso18013CryptoVerifier {
    fn suite(&self) -> Iso18013SignatureSuite {
        self.suite
    }

    fn verify(&self, sig_structure: &[u8], signature: &[u8]) -> Result<(), CoseError> {
        let algorithm = self.suite.crypto_algorithm()?;
        if signature.len() != self.suite.curve().signature_length()? {
            return Err(CoseError::InvalidSignatureEncoding);
        }
        let backend_signature = Zeroizing::new(backend_signature_from_cose(algorithm, signature)?);
        reallyme_crypto::dispatch::verify(
            algorithm,
            &self.public_key,
            sig_structure,
            &backend_signature,
        )
        .map_err(verify_error_from_algorithm_error)
    }
}

impl ZeroizeOnDrop for Iso18013CryptoVerifier {}
