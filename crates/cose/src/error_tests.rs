// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::{
    AeadBackend, AeadFailureKind, CryptoError, KeyWrapAlgorithm, KeyWrapFailureKind,
    KeyWrapOperation, SignatureFailureKind,
};

use super::{
    decrypt_error_from_crypto_error, key_unwrap_error_from_crypto_error,
    sign_error_from_signature_failure, verify_error_from_signature_failure, CoseError,
};

#[test]
fn backend_invalid_message_does_not_implicate_key_material() {
    assert_eq!(
        sign_error_from_signature_failure(SignatureFailureKind::InvalidMessage),
        CoseError::Crypto
    );
    assert_eq!(
        verify_error_from_signature_failure(SignatureFailureKind::InvalidMessage),
        CoseError::Crypto
    );
}

#[test]
fn decrypt_error_mapping_preserves_authentication_and_backend_semantics() {
    let authentication = CryptoError::AeadDecrypt {
        backend: AeadBackend::Native,
        kind: AeadFailureKind::AuthenticationFailed,
    };
    let backend = CryptoError::AeadDecrypt {
        backend: AeadBackend::Native,
        kind: AeadFailureKind::BackendFailure,
    };

    assert_eq!(
        decrypt_error_from_crypto_error(authentication),
        CoseError::AuthenticationFailed,
    );
    assert_eq!(decrypt_error_from_crypto_error(backend), CoseError::Crypto);
}

#[test]
fn key_unwrap_error_mapping_separates_shape_integrity_and_backend_failures() {
    let error = |kind| CryptoError::KeyWrap {
        algorithm: KeyWrapAlgorithm::Aes256Kw,
        operation: KeyWrapOperation::Unwrap,
        kind,
    };

    assert_eq!(
        key_unwrap_error_from_crypto_error(error(KeyWrapFailureKind::IntegrityCheckFailed)),
        CoseError::KeyUnwrapFailed,
    );
    assert_eq!(
        key_unwrap_error_from_crypto_error(error(KeyWrapFailureKind::InvalidWrappedLength)),
        CoseError::InvalidRecipient,
    );
    assert_eq!(
        key_unwrap_error_from_crypto_error(error(KeyWrapFailureKind::BackendFailure)),
        CoseError::Crypto,
    );
}
