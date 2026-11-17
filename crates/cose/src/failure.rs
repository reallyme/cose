// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

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

pub(crate) use crate::error::CoseErrorReason as CoseFailureReason;

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
    #[cfg(feature = "wire")]
    pub(crate) const fn origin(&self) -> CoseFailureOrigin {
        self.origin
    }

    #[cfg(feature = "wire")]
    pub(crate) const fn branch(&self) -> CoseFailureBranch {
        self.branch
    }

    #[cfg(feature = "wire")]
    pub(crate) const fn reason(&self) -> CoseFailureReason {
        self.reason
    }

    /// Converts a semantic failure without changing its protobuf reason.
    ///
    /// Every current semantic reason is safe for native exposure because the
    /// public error contains no dynamic context. Boundary-only reasons
    /// such as malformed protobuf are introduced separately by adapters and
    /// are not represented as semantic reasons.
    pub(crate) const fn into_native_error(self) -> CoseError {
        CoseError::from_reason(self.reason)
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
        let reason = error.reason();
        match buffa::Enumeration::to_i32(&reason) {
            200..=299 => Self::provider(reason),
            300..=399 => Self::backend(reason),
            _ => Self::caller(reason),
        }
    }
}

#[cfg(test)]
#[cfg(not(feature = "wire"))]
#[path = "failure/test_accessors.rs"]
mod test_accessors;

impl From<CoseFailure> for CoseError {
    fn from(failure: CoseFailure) -> Self {
        failure.into_native_error()
    }
}
