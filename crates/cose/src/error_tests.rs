// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::CryptoError;

use super::{
    decrypt_error_from_crypto_error, key_unwrap_error_from_crypto_error,
    signature_error_from_algorithm_error, CoseError,
};

#[test]
fn signature_error_mapping_preserves_key_signature_and_provider_failures() {
    for (error, expected) in [
        (CryptoError::PRIMITIVE_INVALID_PARAMETER, CoseError::Crypto),
        (CryptoError::BACKEND_INTERNAL, CoseError::Crypto),
        (
            CryptoError::PRIMITIVE_INVALID_KEY,
            CoseError::InvalidKeyMaterial,
        ),
        (
            CryptoError::PRIMITIVE_INVALID_PUBLIC_KEY,
            CoseError::InvalidKeyMaterial,
        ),
        (
            CryptoError::PRIMITIVE_INVALID_PRIVATE_KEY,
            CoseError::InvalidKeyMaterial,
        ),
        (
            CryptoError::PROVIDER_HARDWARE_REJECTED_KEY,
            CoseError::InvalidKeyMaterial,
        ),
        (
            CryptoError::PRIMITIVE_INVALID_SIGNATURE,
            CoseError::InvalidSignature,
        ),
        (
            CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM,
            CoseError::UnsupportedAlgorithm,
        ),
        (
            CryptoError::PROVIDER_UNAVAILABLE,
            CoseError::ProviderUnavailable,
        ),
        (
            CryptoError::PROVIDER_HARDWARE_UNAVAILABLE,
            CoseError::ProviderUnavailable,
        ),
    ] {
        assert_eq!(signature_error_from_algorithm_error(error), expected);
    }
}

#[test]
fn decrypt_error_mapping_preserves_authentication_and_backend_semantics() {
    for (error, expected) in [
        (
            CryptoError::PRIMITIVE_AUTHENTICATION_FAILED,
            CoseError::AuthenticationFailed,
        ),
        (
            CryptoError::PRIMITIVE_INVALID_LENGTH,
            CoseError::InvalidFormat,
        ),
        (
            CryptoError::PRIMITIVE_MALFORMED_CIPHERTEXT,
            CoseError::InvalidFormat,
        ),
        (
            CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
            CoseError::ResourceLimitExceeded,
        ),
        (CryptoError::PRIMITIVE_INVALID_KEY, CoseError::Crypto),
        (CryptoError::BACKEND_INTERNAL, CoseError::Crypto),
    ] {
        assert_eq!(decrypt_error_from_crypto_error(error), expected);
    }
}

#[test]
fn key_unwrap_error_mapping_separates_shape_integrity_and_backend_failures() {
    for (error, expected) in [
        (
            CryptoError::PRIMITIVE_AUTHENTICATION_FAILED,
            CoseError::KeyUnwrapFailed,
        ),
        (
            CryptoError::PRIMITIVE_INVALID_LENGTH,
            CoseError::InvalidRecipient,
        ),
        (
            CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
            CoseError::ResourceLimitExceeded,
        ),
        (CryptoError::PRIMITIVE_INVALID_KEY, CoseError::Crypto),
        (CryptoError::BACKEND_INTERNAL, CoseError::Crypto),
    ] {
        assert_eq!(key_unwrap_error_from_crypto_error(error), expected);
    }
}
