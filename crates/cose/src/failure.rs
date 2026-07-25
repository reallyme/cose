// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Canonical internal COSE failure classification.

use crate::CoseError;

/// Component responsible for a failed COSE operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoseFailureOrigin {
    /// Caller-controlled input or COSE semantic validation failed.
    Caller,
    /// Algorithm selection or provider availability failed.
    Provider,
    /// Cryptographic backend or internal execution failed.
    Backend,
}

/// Structured external error branch selected for a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoseFailureBranch {
    /// COSE input, structure, key material, or authentication semantics failed.
    Primitive,
    /// Provider selection or availability failed.
    Provider,
    /// Backend execution failed without caller-safe detail.
    Backend,
}

/// Exact, allocation-free semantic reason retained across COSE boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoseFailureReason {
    CommonCbor,
    CommonUnsupportedAlgorithm,
    Sign1MissingPayload,
    Sign1InvalidSignature,
    Sign1InvalidSignatureEncoding,
    CommonCryptoFailed,
    ProviderUnavailable,
    MultikeyInvalidMultikey,
    KeyMissingKeyMaterial,
    KeyInvalidKeyMaterial,
    Sign1MissingKid,
    Sign1KeyNotResolved,
    CommonInvalidFormat,
    CommonResourceLimitExceeded,
    CommonNonCanonicalCbor,
    CommonUnexpectedCborTag,
    CommonDuplicateMapLabel,
    Sign1UnsupportedCriticalHeader,
    Sign1UnprotectedHeaderNotAllowed,
    Sign1MissingPrivateKey,
    #[cfg(feature = "wire")]
    Sign1KidKeyMismatch,
    EncryptMissingCiphertext,
    EncryptInvalidIv,
    EncryptInvalidRecipient,
    EncryptMissingEncapsulatedKey,
    EncryptInvalidEncapsulatedKey,
    EncryptAuthenticationFailed,
    EncryptKeyUnwrapFailed,
    EncryptKidMismatch,
    #[cfg(feature = "cose-crypto")]
    EncryptMissingKid,
    #[cfg(feature = "cose-crypto")]
    EncryptUnprotectedHeaderNotAllowed,
}

/// Canonical internal failure shared by semantic functions and adapters.
///
/// Fields remain private so invalid origin/branch combinations cannot be
/// assembled outside the canonical constructors. The type carries only fixed
/// enums and therefore cannot retain secrets, PII, raw input, or backend text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoseFailure {
    origin: CoseFailureOrigin,
    branch: CoseFailureBranch,
    reason: CoseFailureReason,
}

impl CoseFailure {
    #[cfg(any(feature = "wire", test))]
    pub(crate) const fn origin(&self) -> CoseFailureOrigin {
        self.origin
    }

    #[cfg(any(feature = "wire", test))]
    pub(crate) const fn branch(&self) -> CoseFailureBranch {
        self.branch
    }

    #[cfg(any(feature = "wire", test))]
    pub(crate) const fn reason(&self) -> CoseFailureReason {
        self.reason
    }

    /// Converts a semantic failure to the existing public native error.
    ///
    /// Every current semantic reason is safe for native exposure because the
    /// public error variants contain no dynamic context. Boundary-only reasons
    /// such as malformed protobuf are introduced separately by adapters and
    /// are not represented as semantic reasons.
    pub(crate) const fn into_native_error(self) -> CoseError {
        match self.reason {
            CoseFailureReason::CommonCbor => CoseError::Cbor,
            CoseFailureReason::CommonUnsupportedAlgorithm => CoseError::UnsupportedAlgorithm,
            CoseFailureReason::Sign1MissingPayload => CoseError::MissingPayload,
            CoseFailureReason::Sign1InvalidSignature => CoseError::InvalidSignature,
            CoseFailureReason::Sign1InvalidSignatureEncoding => CoseError::InvalidSignatureEncoding,
            CoseFailureReason::CommonCryptoFailed => CoseError::Crypto,
            CoseFailureReason::ProviderUnavailable => CoseError::ProviderUnavailable,
            CoseFailureReason::MultikeyInvalidMultikey => CoseError::InvalidMultikey,
            CoseFailureReason::KeyMissingKeyMaterial => CoseError::MissingKeyMaterial,
            CoseFailureReason::KeyInvalidKeyMaterial => CoseError::InvalidKeyMaterial,
            CoseFailureReason::Sign1MissingKid => CoseError::MissingKid,
            CoseFailureReason::Sign1KeyNotResolved => CoseError::KeyNotResolved,
            CoseFailureReason::CommonInvalidFormat => CoseError::InvalidFormat,
            CoseFailureReason::CommonResourceLimitExceeded => CoseError::ResourceLimitExceeded,
            CoseFailureReason::CommonNonCanonicalCbor => CoseError::NonCanonicalCbor,
            CoseFailureReason::CommonUnexpectedCborTag => CoseError::UnexpectedCborTag,
            CoseFailureReason::CommonDuplicateMapLabel => CoseError::DuplicateMapLabel,
            CoseFailureReason::Sign1UnsupportedCriticalHeader => {
                CoseError::UnsupportedCriticalHeader
            }
            CoseFailureReason::Sign1UnprotectedHeaderNotAllowed => {
                CoseError::UnprotectedHeaderNotAllowed
            }
            CoseFailureReason::Sign1MissingPrivateKey => CoseError::MissingPrivateKey,
            // The native resolver API has no separate expected-kid input. This
            // semantic reason is therefore reachable only from structured
            // adapters and degrades to the stable unresolved-key variant
            // if a future native adapter elects to expose the same operation.
            #[cfg(feature = "wire")]
            CoseFailureReason::Sign1KidKeyMismatch => CoseError::KeyNotResolved,
            CoseFailureReason::EncryptMissingCiphertext => CoseError::MissingCiphertext,
            CoseFailureReason::EncryptInvalidIv => CoseError::InvalidIv,
            CoseFailureReason::EncryptInvalidRecipient => CoseError::InvalidRecipient,
            CoseFailureReason::EncryptMissingEncapsulatedKey => CoseError::MissingEncapsulatedKey,
            CoseFailureReason::EncryptInvalidEncapsulatedKey => CoseError::InvalidEncapsulatedKey,
            CoseFailureReason::EncryptAuthenticationFailed => CoseError::AuthenticationFailed,
            CoseFailureReason::EncryptKeyUnwrapFailed => CoseError::KeyUnwrapFailed,
            CoseFailureReason::EncryptKidMismatch => CoseError::KidMismatch,
            #[cfg(feature = "cose-crypto")]
            CoseFailureReason::EncryptMissingKid => CoseError::MissingKid,
            #[cfg(feature = "cose-crypto")]
            CoseFailureReason::EncryptUnprotectedHeaderNotAllowed => {
                CoseError::UnprotectedHeaderNotAllowed
            }
        }
    }

    const fn caller(reason: CoseFailureReason) -> Self {
        Self {
            origin: CoseFailureOrigin::Caller,
            branch: CoseFailureBranch::Primitive,
            reason,
        }
    }

    const fn provider(reason: CoseFailureReason) -> Self {
        Self {
            origin: CoseFailureOrigin::Provider,
            branch: CoseFailureBranch::Provider,
            reason,
        }
    }

    const fn backend(reason: CoseFailureReason) -> Self {
        Self {
            origin: CoseFailureOrigin::Backend,
            branch: CoseFailureBranch::Backend,
            reason,
        }
    }

    #[cfg(feature = "wire")]
    pub(crate) const fn sign1_kid_key_mismatch() -> Self {
        Self::caller(CoseFailureReason::Sign1KidKeyMismatch)
    }

    #[cfg(feature = "cose-crypto")]
    pub(crate) fn from_encrypt_error(error: CoseError) -> Self {
        match error {
            CoseError::MissingKid => Self::caller(CoseFailureReason::EncryptMissingKid),
            CoseError::UnprotectedHeaderNotAllowed => {
                Self::caller(CoseFailureReason::EncryptUnprotectedHeaderNotAllowed)
            }
            other => Self::from(other),
        }
    }
}

impl From<CoseError> for CoseFailure {
    fn from(error: CoseError) -> Self {
        match error {
            CoseError::Cbor => Self::caller(CoseFailureReason::CommonCbor),
            CoseError::UnsupportedAlgorithm => {
                Self::provider(CoseFailureReason::CommonUnsupportedAlgorithm)
            }
            CoseError::MissingPayload => Self::caller(CoseFailureReason::Sign1MissingPayload),
            CoseError::InvalidSignature => Self::caller(CoseFailureReason::Sign1InvalidSignature),
            CoseError::InvalidSignatureEncoding => {
                Self::caller(CoseFailureReason::Sign1InvalidSignatureEncoding)
            }
            CoseError::Crypto => Self::backend(CoseFailureReason::CommonCryptoFailed),
            CoseError::ProviderUnavailable => {
                Self::provider(CoseFailureReason::ProviderUnavailable)
            }
            CoseError::InvalidMultikey => Self::caller(CoseFailureReason::MultikeyInvalidMultikey),
            CoseError::MissingKeyMaterial => Self::caller(CoseFailureReason::KeyMissingKeyMaterial),
            CoseError::InvalidKeyMaterial => Self::caller(CoseFailureReason::KeyInvalidKeyMaterial),
            CoseError::MissingKid => Self::caller(CoseFailureReason::Sign1MissingKid),
            CoseError::KeyNotResolved => Self::caller(CoseFailureReason::Sign1KeyNotResolved),
            CoseError::InvalidFormat => Self::caller(CoseFailureReason::CommonInvalidFormat),
            CoseError::ResourceLimitExceeded => {
                Self::caller(CoseFailureReason::CommonResourceLimitExceeded)
            }
            CoseError::NonCanonicalCbor => Self::caller(CoseFailureReason::CommonNonCanonicalCbor),
            CoseError::UnexpectedCborTag => {
                Self::caller(CoseFailureReason::CommonUnexpectedCborTag)
            }
            CoseError::DuplicateMapLabel => {
                Self::caller(CoseFailureReason::CommonDuplicateMapLabel)
            }
            CoseError::UnsupportedCriticalHeader => {
                Self::caller(CoseFailureReason::Sign1UnsupportedCriticalHeader)
            }
            CoseError::UnprotectedHeaderNotAllowed => {
                Self::caller(CoseFailureReason::Sign1UnprotectedHeaderNotAllowed)
            }
            CoseError::MissingPrivateKey => Self::caller(CoseFailureReason::Sign1MissingPrivateKey),
            CoseError::MissingCiphertext => {
                Self::caller(CoseFailureReason::EncryptMissingCiphertext)
            }
            CoseError::InvalidIv => Self::caller(CoseFailureReason::EncryptInvalidIv),
            CoseError::InvalidRecipient => Self::caller(CoseFailureReason::EncryptInvalidRecipient),
            CoseError::MissingEncapsulatedKey => {
                Self::caller(CoseFailureReason::EncryptMissingEncapsulatedKey)
            }
            CoseError::InvalidEncapsulatedKey => {
                Self::caller(CoseFailureReason::EncryptInvalidEncapsulatedKey)
            }
            CoseError::AuthenticationFailed => {
                Self::caller(CoseFailureReason::EncryptAuthenticationFailed)
            }
            CoseError::KeyUnwrapFailed => Self::caller(CoseFailureReason::EncryptKeyUnwrapFailed),
            CoseError::KidMismatch => Self::caller(CoseFailureReason::EncryptKidMismatch),
        }
    }
}

impl From<CoseFailure> for CoseError {
    fn from(failure: CoseFailure) -> Self {
        failure.into_native_error()
    }
}
