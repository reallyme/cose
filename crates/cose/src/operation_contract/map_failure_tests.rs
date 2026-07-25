// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::failure::CoseFailure;
use crate::CoseError;

use crate::wire::{CoseErrorReason, CoseWireErrorBranch};

use super::map_failure::boundary_error_from_failure;

#[test]
fn canonical_failures_preserve_exact_wire_branch_and_reason() {
    use CoseError as Native;
    use CoseErrorReason as Reason;
    use CoseWireErrorBranch::{Backend, Primitive, Provider};

    let cases = [
        (Native::Cbor, Primitive, Reason::CommonCbor),
        (
            Native::UnsupportedAlgorithm,
            Provider,
            Reason::CommonUnsupportedAlgorithm,
        ),
        (
            Native::MissingPayload,
            Primitive,
            Reason::Sign1MissingPayload,
        ),
        (
            Native::InvalidSignature,
            Primitive,
            Reason::Sign1InvalidSignature,
        ),
        (
            Native::InvalidSignatureEncoding,
            Primitive,
            Reason::Sign1InvalidSignatureEncoding,
        ),
        (Native::Crypto, Backend, Reason::CommonCryptoFailed),
        (
            Native::ProviderUnavailable,
            Provider,
            Reason::ProviderUnavailable,
        ),
        (
            Native::InvalidMultikey,
            Primitive,
            Reason::MultikeyInvalidMultikey,
        ),
        (
            Native::MissingKeyMaterial,
            Primitive,
            Reason::KeyMissingKeyMaterial,
        ),
        (
            Native::InvalidKeyMaterial,
            Primitive,
            Reason::KeyInvalidKeyMaterial,
        ),
        (Native::MissingKid, Primitive, Reason::Sign1MissingKid),
        (
            Native::KeyNotResolved,
            Primitive,
            Reason::Sign1KeyNotResolved,
        ),
        (
            Native::InvalidFormat,
            Primitive,
            Reason::CommonInvalidFormat,
        ),
        (
            Native::ResourceLimitExceeded,
            Primitive,
            Reason::CommonResourceLimitExceeded,
        ),
        (
            Native::NonCanonicalCbor,
            Primitive,
            Reason::CommonNonCanonicalCbor,
        ),
        (
            Native::UnexpectedCborTag,
            Primitive,
            Reason::CommonUnexpectedCborTag,
        ),
        (
            Native::DuplicateMapLabel,
            Primitive,
            Reason::CommonDuplicateMapLabel,
        ),
        (
            Native::UnsupportedCriticalHeader,
            Primitive,
            Reason::Sign1UnsupportedCriticalHeader,
        ),
        (
            Native::UnprotectedHeaderNotAllowed,
            Primitive,
            Reason::Sign1UnprotectedHeaderNotAllowed,
        ),
        (
            Native::MissingPrivateKey,
            Primitive,
            Reason::Sign1MissingPrivateKey,
        ),
        (
            Native::MissingCiphertext,
            Primitive,
            Reason::EncryptMissingCiphertext,
        ),
        (Native::InvalidIv, Primitive, Reason::EncryptInvalidIv),
        (
            Native::InvalidRecipient,
            Primitive,
            Reason::EncryptInvalidRecipient,
        ),
        (
            Native::MissingEncapsulatedKey,
            Primitive,
            Reason::EncryptMissingEncapsulatedKey,
        ),
        (
            Native::InvalidEncapsulatedKey,
            Primitive,
            Reason::EncryptInvalidEncapsulatedKey,
        ),
        (
            Native::AuthenticationFailed,
            Primitive,
            Reason::EncryptAuthenticationFailed,
        ),
        (
            Native::KeyUnwrapFailed,
            Primitive,
            Reason::EncryptKeyUnwrapFailed,
        ),
        (Native::KidMismatch, Primitive, Reason::EncryptKidMismatch),
    ];

    for (native, expected_branch, expected_reason) in cases {
        let wire = boundary_error_from_failure(CoseFailure::from(native));
        assert_eq!(wire.branch(), expected_branch);
        assert_eq!(wire.reason(), expected_reason);
    }
}
