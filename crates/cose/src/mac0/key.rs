// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::hmac::{self, HmacKey};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::error::{from_crypto_error, CoseMac0ErrorReason};
use super::{CoseMac0Error, CoseMacAlgorithm};

/// Owned, zeroizing direct MAC key bound to one exact COSE registration.
///
/// Key material cannot be exported, cloned, serialized, or formatted. The
/// inner primitive key is protected by a secrecy wrapper and zeroizes on drop.
pub struct CoseMacKey {
    algorithm: CoseMacAlgorithm,
    secret: SecretBox<HmacKey>,
}

impl CoseMacKey {
    /// Consume zeroizing key bytes and bind them to an exact MAC algorithm.
    ///
    /// The input owner is wiped on success and failure. Callers must separately
    /// wipe any earlier copies created when importing or deriving the key.
    ///
    /// # Errors
    ///
    /// Returns [`CoseMac0ErrorReason::InvalidKeyLength`] unless the key length
    /// equals [`CoseMacAlgorithm::key_length`]. Primitive failures are typed.
    pub fn new(
        algorithm: CoseMacAlgorithm,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Self, CoseMac0Error> {
        if bytes.len() != algorithm.key_length() {
            return Err(CoseMac0ErrorReason::InvalidKeyLength.into());
        }
        let key = HmacKey::from_slice(&bytes).map_err(from_crypto_error)?;
        Ok(Self {
            algorithm,
            secret: SecretBox::new(Box::new(key)),
        })
    }

    /// Return the algorithm bound to this key without exposing material.
    #[must_use]
    pub const fn algorithm(&self) -> CoseMacAlgorithm {
        self.algorithm
    }

    pub(super) fn verify(&self, message: &[u8], tag: &[u8]) -> Result<(), CoseMac0Error> {
        if self.algorithm == CoseMacAlgorithm::Hmac256_64 {
            // The primitive's verifier accepts full tags only. RFC 9053's
            // left-truncated registration therefore uses its zeroizing tag
            // owner and the same library's constant-time comparison boundary.
            let computed = hmac::authenticate(
                self.algorithm.primitive(),
                self.secret.expose_secret(),
                message,
            )
            .map_err(from_crypto_error)?;
            let expected = computed
                .as_bytes()
                .get(..self.algorithm.tag_length())
                .ok_or(CoseMac0ErrorReason::BackendFailure)?;
            if reallyme_crypto::operations::constant_time::equal(expected, tag) {
                Ok(())
            } else {
                Err(CoseMac0ErrorReason::AuthenticationFailed.into())
            }
        } else {
            hmac::verify(
                self.algorithm.primitive(),
                self.secret.expose_secret(),
                message,
                tag,
            )
            .map_err(from_crypto_error)
        }
    }
}

// Both nested owners zeroize their contents, including during early returns.
impl ZeroizeOnDrop for CoseMacKey {}
