// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::failure::{CoseFailure, CoseFailureBranch, CoseFailureOrigin, CoseFailureReason};
use crate::CoseError;

#[test]
fn every_native_error_has_a_lossless_canonical_failure() {
    for (error, origin, branch, reason) in native_error_cases() {
        let failure = CoseFailure::from(error);

        assert_eq!(failure.origin(), origin);
        assert_eq!(failure.branch(), branch);
        assert_eq!(failure.reason(), reason);

        let remapped = CoseFailure::from(failure.into_native_error());
        assert_eq!(remapped, failure);
    }
}

fn native_error_cases() -> Vec<(
    CoseError,
    CoseFailureOrigin,
    CoseFailureBranch,
    CoseFailureReason,
)> {
    use CoseError as Error;
    use CoseFailureBranch::{Backend as BackendBranch, Primitive, Provider as ProviderBranch};
    use CoseFailureOrigin::{Backend, Caller, Provider};
    use CoseFailureReason as Reason;

    vec![
        (Error::Cbor, Caller, Primitive, Reason::CommonCbor),
        (
            Error::UnsupportedAlgorithm,
            Provider,
            ProviderBranch,
            Reason::CommonUnsupportedAlgorithm,
        ),
        (
            Error::MissingPayload,
            Caller,
            Primitive,
            Reason::Sign1MissingPayload,
        ),
        (
            Error::InvalidSignature,
            Caller,
            Primitive,
            Reason::Sign1InvalidSignature,
        ),
        (
            Error::InvalidSignatureEncoding,
            Caller,
            Primitive,
            Reason::Sign1InvalidSignatureEncoding,
        ),
        (
            Error::Crypto,
            Backend,
            BackendBranch,
            Reason::CommonCryptoFailed,
        ),
        (
            Error::ProviderUnavailable,
            Provider,
            ProviderBranch,
            Reason::ProviderUnavailable,
        ),
        (
            Error::InvalidMultikey,
            Caller,
            Primitive,
            Reason::MultikeyInvalidMultikey,
        ),
        (
            Error::MissingKeyMaterial,
            Caller,
            Primitive,
            Reason::KeyMissingKeyMaterial,
        ),
        (
            Error::InvalidKeyMaterial,
            Caller,
            Primitive,
            Reason::KeyInvalidKeyMaterial,
        ),
        (
            Error::MissingKid,
            Caller,
            Primitive,
            Reason::Sign1MissingKid,
        ),
        (
            Error::KeyNotResolved,
            Caller,
            Primitive,
            Reason::Sign1KeyNotResolved,
        ),
        (
            Error::InvalidFormat,
            Caller,
            Primitive,
            Reason::CommonInvalidFormat,
        ),
        (
            Error::ResourceLimitExceeded,
            Caller,
            Primitive,
            Reason::CommonResourceLimitExceeded,
        ),
        (
            Error::NonCanonicalCbor,
            Caller,
            Primitive,
            Reason::CommonNonCanonicalCbor,
        ),
        (
            Error::UnexpectedCborTag,
            Caller,
            Primitive,
            Reason::CommonUnexpectedCborTag,
        ),
        (
            Error::DuplicateMapLabel,
            Caller,
            Primitive,
            Reason::CommonDuplicateMapLabel,
        ),
        (
            Error::UnsupportedCriticalHeader,
            Caller,
            Primitive,
            Reason::Sign1UnsupportedCriticalHeader,
        ),
        (
            Error::UnprotectedHeaderNotAllowed,
            Caller,
            Primitive,
            Reason::Sign1UnprotectedHeaderNotAllowed,
        ),
        (
            Error::MissingPrivateKey,
            Caller,
            Primitive,
            Reason::Sign1MissingPrivateKey,
        ),
        (
            Error::MissingCiphertext,
            Caller,
            Primitive,
            Reason::EncryptMissingCiphertext,
        ),
        (
            Error::InvalidIv,
            Caller,
            Primitive,
            Reason::EncryptInvalidIv,
        ),
        (
            Error::InvalidRecipient,
            Caller,
            Primitive,
            Reason::EncryptInvalidRecipient,
        ),
        (
            Error::MissingEncapsulatedKey,
            Caller,
            Primitive,
            Reason::EncryptMissingEncapsulatedKey,
        ),
        (
            Error::InvalidEncapsulatedKey,
            Caller,
            Primitive,
            Reason::EncryptInvalidEncapsulatedKey,
        ),
        (
            Error::AuthenticationFailed,
            Caller,
            Primitive,
            Reason::EncryptAuthenticationFailed,
        ),
        (
            Error::KeyUnwrapFailed,
            Caller,
            Primitive,
            Reason::EncryptKeyUnwrapFailed,
        ),
        (
            Error::KidMismatch,
            Caller,
            Primitive,
            Reason::EncryptKidMismatch,
        ),
    ]
}
