// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

#[cfg(feature = "cose-crypto")]
use reallyme_crypto::core::{CryptoError, CryptoErrorReason};
#[cfg(feature = "cose-crypto")]
use reallyme_crypto::dispatch::AlgorithmError;

/// Fixed generated reason retained without diagnostic or input allocation.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("COSE failure: {reason:?}")]
pub struct CoseError {
    reason: CoseErrorReason,
}

pub use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseErrorReason;

impl CoseError {
    /// Return the authoritative generated reason without loss of precision.
    #[must_use]
    pub const fn reason(self) -> CoseErrorReason {
        self.reason
    }
    /// Construct a domain failure from a validated generated reason.
    pub(crate) const fn from_reason(reason: CoseErrorReason) -> Self {
        Self {
            reason: match reason {
                CoseErrorReason::Unspecified => CoseErrorReason::BackendInternal,
                other => other,
            },
        }
    }
}

impl From<CoseErrorReason> for CoseError {
    fn from(reason: CoseErrorReason) -> Self {
        Self::from_reason(reason)
    }
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn signature_error_from_algorithm_error(error: AlgorithmError) -> CoseError {
    use CryptoErrorReason as Reason;
    match error.reason() {
        Reason::ProviderUnsupportedAlgorithm => CoseError::UnsupportedAlgorithm,
        Reason::ProviderUnavailable | Reason::ProviderHardwareUnavailable => {
            CoseError::ProviderUnavailable
        }
        Reason::PrimitiveInvalidKey
        | Reason::PrimitiveInvalidPublicKey
        | Reason::PrimitiveInvalidPrivateKey
        | Reason::ProviderHardwareRejectedKey => CoseError::InvalidKeyMaterial,
        Reason::PrimitiveInvalidSignature => CoseError::InvalidSignature,
        // Public-key validation uses a dummy signature. Only an explicit
        // signature failure shows that the backend accepted the key material.
        _ => CoseError::Crypto,
    }
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn decrypt_error_from_crypto_error(error: CryptoError) -> CoseError {
    use CryptoErrorReason as Reason;
    match error.reason() {
        Reason::PrimitiveAuthenticationFailed => CoseError::AuthenticationFailed,
        Reason::PrimitiveInvalidLength | Reason::PrimitiveMalformedCiphertext => {
            CoseError::InvalidFormat
        }
        Reason::PrimitiveResourceLimitExceeded => CoseError::ResourceLimitExceeded,
        // Content decryption uses an already validated or derived key.
        _ => CoseError::Crypto,
    }
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn key_unwrap_error_from_crypto_error(error: CryptoError) -> CoseError {
    use CryptoErrorReason as Reason;
    match error.reason() {
        Reason::PrimitiveAuthenticationFailed => CoseError::KeyUnwrapFailed,
        Reason::PrimitiveInvalidLength => CoseError::InvalidRecipient,
        Reason::PrimitiveResourceLimitExceeded => CoseError::ResourceLimitExceeded,
        _ => CoseError::Crypto,
    }
}

#[cfg(test)]
#[cfg(feature = "cose-crypto")]
#[path = "error_tests.rs"]
mod tests;
