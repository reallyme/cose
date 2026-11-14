// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::{CryptoError, MacFailureKind};

/// Compatibility name for the shared, schema-defined failure owner.
pub type CoseMac0Error = crate::CoseError;
/// Compatibility name for the sole generated reason enum.
pub use crate::error::CoseErrorReason as CoseMac0ErrorReason;

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
