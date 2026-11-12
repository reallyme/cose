// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{ContainerError, SignatureEncoding, VerificationKey};
use crate::iso18013::Iso18013EcdsaHash;
use zeroize::Zeroizing;

/// Explicit input contract, preventing message/prehash or ECDSA/EdDSA confusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningMode {
    /// Provider hashes the complete message for ECDSA, or performs pure EdDSA.
    Message,
    /// COSE hashes the complete Sig_structure exactly once with this ECDSA hash.
    EcdsaPrehash(Iso18013EcdsaHash),
}

/// Borrowed finalized input; a prehash never masquerades as an ordinary message.
pub enum SigningInput<'a> {
    /// Exact full RFC 9052 Sig_structure.
    Message(&'a [u8]),
    /// Exactly one digest of Sig_structure, with explicit hash identity.
    EcdsaPrehash {
        /// Selected registration's ECDSA hash.
        hash: Iso18013EcdsaHash,
        /// Exact digest, not a message to hash again.
        digest: &'a [u8],
    },
}

/// Opaque non-exporting signing capability with a stable public-key binding.
///
/// No private-key accessor exists. Adapters implement the declared input mode
/// and encoding exactly; errors never include handles or backend diagnostics.
pub trait ContainerSigner {
    /// Validated public key, exact suite and context bound to the private handle.
    fn verification_key(&self) -> &dyn VerificationKey;
    /// Stable message or explicit ECDSA-prehash contract.
    fn input_mode(&self) -> SigningMode;
    /// Stable declared signature encoding, never guessed from length.
    fn signature_encoding(&self) -> SignatureEncoding;
    /// Sign finalized input without exporting the private key.
    ///
    /// # Errors
    /// Returns fixed key, provider, input-mode or backend failures.
    fn sign(&self, input: SigningInput<'_>) -> Result<Zeroizing<Vec<u8>>, ContainerError>;
}
