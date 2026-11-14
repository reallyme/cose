// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

#[cfg(feature = "cose-crypto")]
use reallyme_crypto::core::{
    AeadFailureKind, CryptoError, KeyWrapFailureKind, SignatureFailureKind,
};
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
pub(crate) fn sign_error_from_algorithm_error(error: AlgorithmError) -> CoseError {
    match error {
        AlgorithmError::UnsupportedAlgorithm(_)
        | AlgorithmError::UnsupportedAeadAlgorithm(_)
        | AlgorithmError::UnsupportedHashAlgorithm(_)
        | AlgorithmError::UnsupportedMacAlgorithm(_) => CoseError::UnsupportedAlgorithm,
        AlgorithmError::InvalidKey(_) | AlgorithmError::Crypto(CryptoError::InvalidKey) => {
            CoseError::InvalidKeyMaterial
        }
        AlgorithmError::SignatureInvalid(_) => CoseError::InvalidSignature,
        AlgorithmError::Crypto(CryptoError::Signature { kind, .. }) => {
            sign_error_from_signature_failure(kind)
        }
        AlgorithmError::Crypto(_) => CoseError::Crypto,
        // Crypto marks this enum non-exhaustive so providers can add precise
        // failure modes. Unknown future cases must fail closed without leaking
        // backend detail through COSE's public error boundary.
        _ => CoseError::Crypto,
    }
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn verify_error_from_algorithm_error(error: AlgorithmError) -> CoseError {
    match error {
        AlgorithmError::UnsupportedAlgorithm(_)
        | AlgorithmError::UnsupportedAeadAlgorithm(_)
        | AlgorithmError::UnsupportedHashAlgorithm(_)
        | AlgorithmError::UnsupportedMacAlgorithm(_) => CoseError::UnsupportedAlgorithm,
        AlgorithmError::InvalidKey(_) | AlgorithmError::Crypto(CryptoError::InvalidKey) => {
            CoseError::InvalidKeyMaterial
        }
        AlgorithmError::SignatureInvalid(_) => CoseError::InvalidSignature,
        AlgorithmError::Crypto(CryptoError::Signature { kind, .. }) => {
            verify_error_from_signature_failure(kind)
        }
        AlgorithmError::Crypto(_) => CoseError::Crypto,
        // Crypto marks this enum non-exhaustive so providers can add precise
        // failure modes. Unknown future cases must fail closed without leaking
        // backend detail through COSE's public error boundary.
        _ => CoseError::Crypto,
    }
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn decrypt_error_from_crypto_error(error: CryptoError) -> CoseError {
    match error {
        CryptoError::AeadDecrypt { kind, .. } => match kind {
            AeadFailureKind::AuthenticationFailed => CoseError::AuthenticationFailed,
            AeadFailureKind::ShortCiphertext => CoseError::InvalidFormat,
            AeadFailureKind::LengthOverflow => CoseError::ResourceLimitExceeded,
            AeadFailureKind::InvalidKeyMaterial
            | AeadFailureKind::InvalidOutputLength
            | AeadFailureKind::BackendFailure => CoseError::Crypto,
            // New backend failure classes must not be reported as caller
            // authentication failures without an explicit COSE decision.
            _ => CoseError::Crypto,
        },
        CryptoError::InvalidCiphertextLength { .. } => CoseError::InvalidFormat,
        CryptoError::InvalidKey => CoseError::Crypto,
        _ => CoseError::Crypto,
    }
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn key_unwrap_error_from_crypto_error(error: CryptoError) -> CoseError {
    match error {
        CryptoError::KeyWrap { kind, .. } => match kind {
            KeyWrapFailureKind::IntegrityCheckFailed => CoseError::KeyUnwrapFailed,
            KeyWrapFailureKind::InvalidWrappedLength => CoseError::InvalidRecipient,
            KeyWrapFailureKind::LengthOverflow => CoseError::ResourceLimitExceeded,
            KeyWrapFailureKind::InvalidKekLength
            | KeyWrapFailureKind::InvalidPlaintextLength
            | KeyWrapFailureKind::BackendFailure => CoseError::Crypto,
            // Unknown future key-wrap failures are operational until COSE
            // deliberately assigns a narrower public meaning.
            _ => CoseError::Crypto,
        },
        _ => CoseError::Crypto,
    }
}

#[cfg(feature = "cose-crypto")]
fn sign_error_from_signature_failure(kind: SignatureFailureKind) -> CoseError {
    match kind {
        SignatureFailureKind::InvalidPrivateKey
        | SignatureFailureKind::InvalidPublicKey
        | SignatureFailureKind::SecureEnclaveRejectedKey => CoseError::InvalidKeyMaterial,
        SignatureFailureKind::InvalidSignature => CoseError::InvalidSignature,
        SignatureFailureKind::SecureEnclaveUnavailable => CoseError::ProviderUnavailable,
        SignatureFailureKind::InvalidMessage
        | SignatureFailureKind::BackendFailure
        | SignatureFailureKind::KeyGenerationFailed => CoseError::Crypto,
        // Future provider/backend signature failures are operational crypto
        // failures unless COSE deliberately classifies them more narrowly.
        _ => CoseError::Crypto,
    }
}

#[cfg(feature = "cose-crypto")]
fn verify_error_from_signature_failure(kind: SignatureFailureKind) -> CoseError {
    match kind {
        SignatureFailureKind::InvalidPublicKey
        | SignatureFailureKind::InvalidPrivateKey
        | SignatureFailureKind::SecureEnclaveRejectedKey => CoseError::InvalidKeyMaterial,
        SignatureFailureKind::InvalidSignature => CoseError::InvalidSignature,
        SignatureFailureKind::SecureEnclaveUnavailable => CoseError::ProviderUnavailable,
        SignatureFailureKind::InvalidMessage
        | SignatureFailureKind::BackendFailure
        | SignatureFailureKind::KeyGenerationFailed => CoseError::Crypto,
        // Future provider/backend signature failures are operational crypto
        // failures unless COSE deliberately classifies them more narrowly.
        _ => CoseError::Crypto,
    }
}

#[cfg(test)]
#[cfg(feature = "cose-crypto")]
#[path = "error_tests.rs"]
mod tests;
