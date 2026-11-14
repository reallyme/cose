// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto. Regenerate with scripts/generate_cose_contract.mjs.

use crate::CoseError;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseErrorReason;

#[allow(non_upper_case_globals)]
impl CoseError {
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const Cbor: Self = Self::from_reason(CoseErrorReason::CommonCbor);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const InvalidFormat: Self = Self::from_reason(CoseErrorReason::CommonInvalidFormat);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const ResourceLimitExceeded: Self =
        Self::from_reason(CoseErrorReason::CommonResourceLimitExceeded);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const NonCanonicalCbor: Self = Self::from_reason(CoseErrorReason::CommonNonCanonicalCbor);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const UnexpectedCborTag: Self = Self::from_reason(CoseErrorReason::CommonUnexpectedCborTag);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const DuplicateMapLabel: Self = Self::from_reason(CoseErrorReason::CommonDuplicateMapLabel);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const UnsupportedAlgorithm: Self =
        Self::from_reason(CoseErrorReason::CommonUnsupportedAlgorithm);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const ProviderUnavailable: Self = Self::from_reason(CoseErrorReason::ProviderUnavailable);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const Unavailable: Self = Self::from_reason(CoseErrorReason::ProviderUnavailable);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const Crypto: Self = Self::from_reason(CoseErrorReason::CommonCryptoFailed);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const Backend: Self = Self::from_reason(CoseErrorReason::CommonCryptoFailed);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const MissingPayload: Self = Self::from_reason(CoseErrorReason::Sign1MissingPayload);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const MissingKid: Self = Self::from_reason(CoseErrorReason::Sign1MissingKid);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const KeyNotResolved: Self = Self::from_reason(CoseErrorReason::Sign1KeyNotResolved);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const UnsupportedCriticalHeader: Self =
        Self::from_reason(CoseErrorReason::Sign1UnsupportedCriticalHeader);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const UnprotectedHeaderNotAllowed: Self =
        Self::from_reason(CoseErrorReason::Sign1UnprotectedHeaderNotAllowed);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const InvalidSignature: Self = Self::from_reason(CoseErrorReason::Sign1InvalidSignature);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const MissingPrivateKey: Self = Self::from_reason(CoseErrorReason::Sign1MissingPrivateKey);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const InvalidSignatureEncoding: Self =
        Self::from_reason(CoseErrorReason::Sign1InvalidSignatureEncoding);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const MissingKeyMaterial: Self = Self::from_reason(CoseErrorReason::KeyMissingKeyMaterial);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const InvalidKeyMaterial: Self = Self::from_reason(CoseErrorReason::KeyInvalidKeyMaterial);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const InvalidKey: Self = Self::from_reason(CoseErrorReason::KeyInvalidKeyMaterial);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const InvalidMultikey: Self = Self::from_reason(CoseErrorReason::MultikeyInvalidMultikey);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const MissingCiphertext: Self =
        Self::from_reason(CoseErrorReason::EncryptMissingCiphertext);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const InvalidIv: Self = Self::from_reason(CoseErrorReason::EncryptInvalidIv);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const InvalidRecipient: Self = Self::from_reason(CoseErrorReason::EncryptInvalidRecipient);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const MissingEncapsulatedKey: Self =
        Self::from_reason(CoseErrorReason::EncryptMissingEncapsulatedKey);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const InvalidEncapsulatedKey: Self =
        Self::from_reason(CoseErrorReason::EncryptInvalidEncapsulatedKey);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const AuthenticationFailed: Self =
        Self::from_reason(CoseErrorReason::EncryptAuthenticationFailed);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const KeyUnwrapFailed: Self = Self::from_reason(CoseErrorReason::EncryptKeyUnwrapFailed);
    /// Compatibility spelling; the generated reason is retained exactly.
    pub const KidMismatch: Self = Self::from_reason(CoseErrorReason::EncryptKidMismatch);
}
