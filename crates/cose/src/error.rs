// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[cfg(feature = "cose-crypto")]
use reallyme_crypto::core::{
    AeadFailureKind, CryptoError, KeyWrapFailureKind, SignatureFailureKind,
};
#[cfg(feature = "cose-crypto")]
use reallyme_crypto::dispatch::AlgorithmError;

/// Error type for COSE encoding, signing, verification, key, and policy operations.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoseError {
    /// CBOR serialization or parsing failed.
    #[error("cbor encoding/decoding error")]
    Cbor,

    /// The requested algorithm is not supported by the current COSE mapping.
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,

    /// A COSE_Sign1 object did not contain an attached payload where one was required.
    #[error("missing payload")]
    MissingPayload,

    /// Signature verification failed for otherwise well-formed signature bytes.
    #[error("invalid signature")]
    InvalidSignature,

    /// Signature bytes were not encoded according to the selected COSE
    /// algorithm's wire format.
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,

    /// The configured cryptographic backend rejected the operation.
    #[error("crypto error")]
    Crypto,

    /// The requested cryptographic provider is unavailable in this runtime.
    #[error("cryptographic provider unavailable")]
    ProviderUnavailable,

    /// A Multikey value was malformed or could not be converted safely.
    #[error("invalid multikey")]
    InvalidMultikey,

    /// Required public or private key bytes were absent.
    #[error("missing key material")]
    MissingKeyMaterial,

    /// Key bytes were present but did not match the expected COSE key shape.
    #[error("invalid key material")]
    InvalidKeyMaterial,

    /// A policy required `kid` / key_id but the COSE object did not provide one.
    #[error("missing kid")]
    MissingKid,

    /// A `kid` was present, but the caller's resolver did not return a key.
    #[error("key not resolved")]
    KeyNotResolved,

    /// The COSE object is structurally invalid for the requested operation.
    #[error("invalid COSE format")]
    InvalidFormat,

    /// Encoded input exceeded the crate's deterministic resource limits.
    #[error("resource limit exceeded")]
    ResourceLimitExceeded,

    /// Encoded input used indefinite-length or otherwise non-canonical CBOR.
    #[error("non-canonical CBOR")]
    NonCanonicalCbor,

    /// Encoded input used CBOR tags outside this crate's supported profile.
    #[error("unexpected CBOR tag")]
    UnexpectedCborTag,

    /// Encoded input repeated a CBOR map label where uniqueness is required.
    #[error("duplicate CBOR map label")]
    DuplicateMapLabel,

    /// A critical protected header was present but is not supported.
    #[error("unsupported critical header")]
    UnsupportedCriticalHeader,

    /// An unprotected header carried fields that must be integrity protected.
    #[error("unprotected header not allowed")]
    UnprotectedHeaderNotAllowed,

    /// Private key material was required but absent.
    #[error("missing private key material")]
    MissingPrivateKey,

    /// A COSE encryption object did not contain an attached ciphertext.
    #[error("missing ciphertext")]
    MissingCiphertext,

    /// A COSE encryption object used an invalid or misplaced IV.
    #[error("invalid IV")]
    InvalidIv,

    /// A COSE encryption object did not contain exactly one supported recipient.
    #[error("invalid recipient")]
    InvalidRecipient,

    /// The recipient did not contain the ML-KEM encapsulated key header.
    #[error("missing encapsulated key")]
    MissingEncapsulatedKey,

    /// The ML-KEM encapsulated key was malformed for the selected parameter set.
    #[error("invalid encapsulated key")]
    InvalidEncapsulatedKey,

    /// The authenticated ciphertext, external AAD, or derived key did not verify.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// AES Key Wrap integrity verification failed for the recipient CEK.
    #[error("key unwrap failed")]
    KeyUnwrapFailed,

    /// A required key identifier was present but did not match the selected key.
    #[error("kid mismatch")]
    KidMismatch,
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
        | SignatureFailureKind::InvalidMessage
        | SignatureFailureKind::SecureEnclaveRejectedKey => CoseError::InvalidKeyMaterial,
        SignatureFailureKind::InvalidSignature => CoseError::InvalidSignature,
        SignatureFailureKind::SecureEnclaveUnavailable => CoseError::ProviderUnavailable,
        SignatureFailureKind::BackendFailure | SignatureFailureKind::KeyGenerationFailed => {
            CoseError::Crypto
        }
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
        | SignatureFailureKind::InvalidMessage
        | SignatureFailureKind::SecureEnclaveRejectedKey => CoseError::InvalidKeyMaterial,
        SignatureFailureKind::InvalidSignature => CoseError::InvalidSignature,
        SignatureFailureKind::SecureEnclaveUnavailable => CoseError::ProviderUnavailable,
        SignatureFailureKind::BackendFailure | SignatureFailureKind::KeyGenerationFailed => {
            CoseError::Crypto
        }
        // Future provider/backend signature failures are operational crypto
        // failures unless COSE deliberately classifies them more narrowly.
        _ => CoseError::Crypto,
    }
}

#[cfg(all(test, feature = "cose-crypto"))]
#[path = "error_tests.rs"]
mod tests;
