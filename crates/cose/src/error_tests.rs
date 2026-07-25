// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_crypto::core::{
    AeadBackend, AeadFailureKind, CryptoError, KeyWrapAlgorithm, KeyWrapFailureKind,
    KeyWrapOperation,
};

use super::{decrypt_error_from_crypto_error, key_unwrap_error_from_crypto_error, CoseError};

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
