// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Fixed failure reasons for the bounded container boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerErrorReason {
    /// Invalid or incomplete CBOR, framing, or header shape.
    Malformed,
    /// Definite/preferred serialization was required.
    Encoding,
    /// A duplicate map label or a label in both header buckets.
    Duplicate,
    /// Unsupported critical semantics.
    Critical,
    /// Input, parser work, nesting, or allocation limit exceeded.
    Limit,
    /// The selected container or header placement contract was violated.
    Profile,
    /// Registration or exact suite is not explicitly permitted.
    Algorithm,
    /// The verification key, curve, or key usage does not match.
    Key,
    /// A required crypto capability is unavailable.
    Provider,
    /// The injected certificate-validation boundary failed.
    CertificateValidation,
    /// Certificate bytes do not match the selected end entity or thumbprint.
    CertificateMismatch,
    /// x5t used an unsupported hash registration.
    ThumbprintAlgorithm,
    /// x5t was not an exact SHA-256 digest.
    ThumbprintLength,
    /// Invalid declared signature encoding, scalar, or width.
    SignatureEncoding,
    /// Signature authentication failed.
    Authentication,
    /// Signer input mode is incompatible with the suite.
    SigningInput,
    /// A provider failed without safe diagnostic context.
    Backend,
}

/// Allocation-free error; it never carries input, certificates, handles, or text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("COSE container failure: {reason:?}")]
pub struct ContainerError {
    reason: ContainerErrorReason,
}

impl ContainerError {
    /// Return the stable domain-specific reason.
    #[must_use]
    pub const fn reason(self) -> ContainerErrorReason {
        self.reason
    }
}

impl From<ContainerErrorReason> for ContainerError {
    fn from(reason: ContainerErrorReason) -> Self {
        Self { reason }
    }
}

impl From<crate::CoseError> for ContainerError {
    fn from(error: crate::CoseError) -> Self {
        use crate::CoseError;
        let reason = match error {
            CoseError::ResourceLimitExceeded => ContainerErrorReason::Limit,
            CoseError::UnsupportedAlgorithm => ContainerErrorReason::Algorithm,
            CoseError::ProviderUnavailable => ContainerErrorReason::Provider,
            CoseError::InvalidKeyMaterial => ContainerErrorReason::Key,
            CoseError::InvalidSignature => ContainerErrorReason::Authentication,
            CoseError::InvalidSignatureEncoding => ContainerErrorReason::SignatureEncoding,
            _ => ContainerErrorReason::Backend,
        };
        reason.into()
    }
}
