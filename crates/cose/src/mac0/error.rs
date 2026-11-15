// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::{CryptoError, CryptoErrorReason as Reason};

/// Compatibility name for the shared, schema-defined failure owner.
pub type CoseMac0Error = crate::CoseError;
/// Compatibility name for the sole generated reason enum.
pub use crate::error::CoseErrorReason as CoseMac0ErrorReason;

pub(super) fn from_crypto_error(error: CryptoError) -> CoseMac0Error {
    let reason = match error.reason() {
        Reason::PrimitiveInvalidKey => CoseMac0ErrorReason::InvalidKeyLength,
        Reason::PrimitiveInvalidTag => CoseMac0ErrorReason::InvalidTagLength,
        Reason::PrimitiveVerificationFailed => CoseMac0ErrorReason::AuthenticationFailed,
        Reason::ProviderUnavailable
        | Reason::ProviderUnsupportedAlgorithm
        | Reason::ProviderUnsupportedBackend => CoseMac0ErrorReason::ProviderUnavailable,
        _ => CoseMac0ErrorReason::BackendFailure,
    };
    reason.into()
}
