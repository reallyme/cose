// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::{CryptoError, MacFailureKind};
use thiserror::Error;

use crate::CoseError;

/// Allocation-free failure reason; never contains input or backend diagnostics.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CoseMac0ErrorReason {
    /// CBOR was truncated, malformed, or followed by trailing data.
    #[error("malformed CBOR")]
    MalformedCbor,
    /// CBOR violated the definite-length, preferred-width profile.
    #[error("non-canonical CBOR")]
    NonCanonicalCbor,
    /// A CBOR tag other than the optional single outer tag 17 was present.
    #[error("unexpected CBOR tag")]
    UnexpectedTag,
    /// The structure or a header had an invalid type or shape.
    #[error("invalid Mac0 structure")]
    InvalidStructure,
    /// A label appeared repeatedly or in both header buckets.
    #[error("duplicate or conflicting header")]
    DuplicateHeader,
    /// The profile requires alg in the protected bucket.
    #[error("missing protected algorithm")]
    MissingProtectedAlgorithm,
    /// An algorithm is unimplemented or absent from the explicit allowlist.
    #[error("unsupported MAC algorithm")]
    UnsupportedAlgorithm,
    /// An integrity-sensitive header was placed in the unprotected bucket.
    #[error("unprotected security header")]
    UnprotectedSecurityHeader,
    /// A critical header was not understood by this profile.
    #[error("unsupported critical header")]
    UnsupportedCriticalHeader,
    /// The payload slot was not null.
    #[error("detached payload required")]
    DetachedPayloadRequired,
    /// The MAC tag did not have the exact registered length.
    #[error("invalid MAC tag length")]
    InvalidTagLength,
    /// The direct key did not have the required hash output length.
    #[error("invalid MAC key length")]
    InvalidKeyLength,
    /// The key was bound to a different exact COSE algorithm.
    #[error("MAC key algorithm mismatch")]
    KeyAlgorithmMismatch,
    /// Authentication failed for a structurally valid message and tag.
    #[error("MAC authentication failed")]
    AuthenticationFailed,
    /// A byte, collection, depth, arithmetic, or allocation limit was exceeded.
    #[error("resource limit exceeded")]
    ResourceLimitExceeded,
    /// A required crypto implementation was unavailable.
    #[error("MAC provider unavailable")]
    ProviderUnavailable,
    /// The crypto backend failed without caller-safe detail.
    #[error("MAC backend failure")]
    BackendFailure,
}

/// Typed Mac0 failure containing only a fixed, non-sensitive reason.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("COSE_Mac0: {reason}")]
pub struct CoseMac0Error {
    reason: CoseMac0ErrorReason,
}

impl CoseMac0Error {
    /// Return the stable, allocation-free failure classification.
    #[must_use]
    pub const fn reason(self) -> CoseMac0ErrorReason {
        self.reason
    }
}

impl From<CoseMac0ErrorReason> for CoseMac0Error {
    fn from(reason: CoseMac0ErrorReason) -> Self {
        Self { reason }
    }
}

impl From<CoseError> for CoseMac0Error {
    fn from(error: CoseError) -> Self {
        let reason = match error {
            CoseError::Cbor => CoseMac0ErrorReason::MalformedCbor,
            CoseError::NonCanonicalCbor => CoseMac0ErrorReason::NonCanonicalCbor,
            CoseError::UnexpectedCborTag => CoseMac0ErrorReason::UnexpectedTag,
            CoseError::DuplicateMapLabel => CoseMac0ErrorReason::DuplicateHeader,
            CoseError::ResourceLimitExceeded => CoseMac0ErrorReason::ResourceLimitExceeded,
            _ => CoseMac0ErrorReason::InvalidStructure,
        };
        reason.into()
    }
}

pub(super) fn from_crypto_error(error: CryptoError) -> CoseMac0Error {
    let reason = match error {
        CryptoError::Mac { kind, .. } => match kind {
            MacFailureKind::InvalidKeyLength => CoseMac0ErrorReason::InvalidKeyLength,
            MacFailureKind::InvalidTagLength => CoseMac0ErrorReason::InvalidTagLength,
            MacFailureKind::VerificationFailed => CoseMac0ErrorReason::AuthenticationFailed,
            _ => CoseMac0ErrorReason::BackendFailure,
        },
        CryptoError::Unsupported => CoseMac0ErrorReason::ProviderUnavailable,
        _ => CoseMac0ErrorReason::BackendFailure,
    };
    reason.into()
}
