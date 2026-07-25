// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Canonical semantic-failure mapping for protobuf adapters.

use crate::failure::{CoseFailure, CoseFailureBranch, CoseFailureOrigin, CoseFailureReason};

use crate::wire::{CoseErrorReason, CoseWireError};

pub(crate) fn boundary_error_from_failure(failure: CoseFailure) -> CoseWireError {
    let reason = reason_from_failure(failure.reason());
    match (failure.origin(), failure.branch()) {
        (CoseFailureOrigin::Caller, CoseFailureBranch::Primitive) => {
            CoseWireError::primitive_internal(reason)
        }
        (CoseFailureOrigin::Provider, CoseFailureBranch::Provider) => {
            CoseWireError::provider_internal(reason)
        }
        (CoseFailureOrigin::Backend, CoseFailureBranch::Backend) => {
            CoseWireError::backend_internal(reason)
        }
        // `CoseFailure` fields are private and its constructors preserve these
        // pairings. This defensive branch still fails closed if that invariant
        // is ever broken by an internal implementation change.
        _ => CoseWireError::backend_internal(CoseErrorReason::BackendInternal),
    }
}

const fn reason_from_failure(reason: CoseFailureReason) -> CoseErrorReason {
    match reason {
        CoseFailureReason::CommonCbor => CoseErrorReason::CommonCbor,
        CoseFailureReason::CommonUnsupportedAlgorithm => {
            CoseErrorReason::CommonUnsupportedAlgorithm
        }
        CoseFailureReason::Sign1MissingPayload => CoseErrorReason::Sign1MissingPayload,
        CoseFailureReason::Sign1InvalidSignature => CoseErrorReason::Sign1InvalidSignature,
        CoseFailureReason::Sign1InvalidSignatureEncoding => {
            CoseErrorReason::Sign1InvalidSignatureEncoding
        }
        CoseFailureReason::CommonCryptoFailed => CoseErrorReason::CommonCryptoFailed,
        CoseFailureReason::ProviderUnavailable => CoseErrorReason::ProviderUnavailable,
        CoseFailureReason::MultikeyInvalidMultikey => CoseErrorReason::MultikeyInvalidMultikey,
        CoseFailureReason::KeyMissingKeyMaterial => CoseErrorReason::KeyMissingKeyMaterial,
        CoseFailureReason::KeyInvalidKeyMaterial => CoseErrorReason::KeyInvalidKeyMaterial,
        CoseFailureReason::Sign1MissingKid => CoseErrorReason::Sign1MissingKid,
        CoseFailureReason::Sign1KeyNotResolved => CoseErrorReason::Sign1KeyNotResolved,
        CoseFailureReason::CommonInvalidFormat => CoseErrorReason::CommonInvalidFormat,
        CoseFailureReason::CommonResourceLimitExceeded => {
            CoseErrorReason::CommonResourceLimitExceeded
        }
        CoseFailureReason::CommonNonCanonicalCbor => CoseErrorReason::CommonNonCanonicalCbor,
        CoseFailureReason::CommonUnexpectedCborTag => CoseErrorReason::CommonUnexpectedCborTag,
        CoseFailureReason::CommonDuplicateMapLabel => CoseErrorReason::CommonDuplicateMapLabel,
        CoseFailureReason::Sign1UnsupportedCriticalHeader => {
            CoseErrorReason::Sign1UnsupportedCriticalHeader
        }
        CoseFailureReason::Sign1UnprotectedHeaderNotAllowed => {
            CoseErrorReason::Sign1UnprotectedHeaderNotAllowed
        }
        CoseFailureReason::Sign1MissingPrivateKey => CoseErrorReason::Sign1MissingPrivateKey,
        CoseFailureReason::Sign1KidKeyMismatch => CoseErrorReason::Sign1KidKeyMismatch,
        CoseFailureReason::EncryptMissingCiphertext => CoseErrorReason::EncryptMissingCiphertext,
        CoseFailureReason::EncryptInvalidIv => CoseErrorReason::EncryptInvalidIv,
        CoseFailureReason::EncryptInvalidRecipient => CoseErrorReason::EncryptInvalidRecipient,
        CoseFailureReason::EncryptMissingEncapsulatedKey => {
            CoseErrorReason::EncryptMissingEncapsulatedKey
        }
        CoseFailureReason::EncryptInvalidEncapsulatedKey => {
            CoseErrorReason::EncryptInvalidEncapsulatedKey
        }
        CoseFailureReason::EncryptAuthenticationFailed => {
            CoseErrorReason::EncryptAuthenticationFailed
        }
        CoseFailureReason::EncryptKeyUnwrapFailed => CoseErrorReason::EncryptKeyUnwrapFailed,
        CoseFailureReason::EncryptKidMismatch => CoseErrorReason::EncryptKidMismatch,
        #[cfg(feature = "cose-crypto")]
        CoseFailureReason::EncryptMissingKid => CoseErrorReason::EncryptMissingKid,
        #[cfg(feature = "cose-crypto")]
        CoseFailureReason::EncryptUnprotectedHeaderNotAllowed => {
            CoseErrorReason::EncryptUnprotectedHeaderNotAllowed
        }
    }
}
