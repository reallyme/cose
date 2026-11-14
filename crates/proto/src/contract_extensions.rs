// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from cose.proto; this companion does not modify Buffa output.

use crate::generated::proto::reallyme::cose::v1::{
    cose_type, CoseErrorReason, CoseSign1Options, CoseType,
};

#[allow(non_upper_case_globals)]
impl CoseErrorReason {
    /// Compatibility spelling for the canonical reason.
    pub const Malformed: Self = Self::CommonCbor;
    /// Compatibility spelling for the canonical reason.
    pub const MalformedCbor: Self = Self::CommonCbor;
    /// Compatibility spelling for the canonical reason.
    pub const InvalidStructure: Self = Self::CommonInvalidFormat;
    /// Compatibility spelling for the canonical reason.
    pub const Limit: Self = Self::CommonResourceLimitExceeded;
    /// Compatibility spelling for the canonical reason.
    pub const ResourceLimitExceeded: Self = Self::CommonResourceLimitExceeded;
    /// Compatibility spelling for the canonical reason.
    pub const Encoding: Self = Self::CommonNonCanonicalCbor;
    /// Compatibility spelling for the canonical reason.
    pub const NonCanonicalCbor: Self = Self::CommonNonCanonicalCbor;
    /// Compatibility spelling for the canonical reason.
    pub const UnexpectedTag: Self = Self::CommonUnexpectedCborTag;
    /// Compatibility spelling for the canonical reason.
    pub const Duplicate: Self = Self::CommonDuplicateMapLabel;
    /// Compatibility spelling for the canonical reason.
    pub const DuplicateHeader: Self = Self::CommonDuplicateMapLabel;
    /// Compatibility spelling for the canonical reason.
    pub const MissingProtectedAlgorithm: Self = Self::CommonMissingProtectedAlgorithm;
    /// Compatibility spelling for the canonical reason.
    pub const AuthenticationFailed: Self = Self::CommonAuthenticationFailed;
    /// Compatibility spelling for the canonical reason.
    pub const Algorithm: Self = Self::CommonUnsupportedAlgorithm;
    /// Compatibility spelling for the canonical reason.
    pub const UnsupportedAlgorithm: Self = Self::CommonUnsupportedAlgorithm;
    /// Compatibility spelling for the canonical reason.
    pub const Provider: Self = Self::ProviderUnavailable;
    /// Compatibility spelling for the canonical reason.
    pub const ThumbprintAlgorithm: Self = Self::ProviderUnsupportedThumbprintAlgorithm;
    /// Compatibility spelling for the canonical reason.
    pub const Backend: Self = Self::CommonCryptoFailed;
    /// Compatibility spelling for the canonical reason.
    pub const BackendFailure: Self = Self::CommonCryptoFailed;
    /// Compatibility spelling for the canonical reason.
    pub const Critical: Self = Self::Sign1UnsupportedCriticalHeader;
    /// Compatibility spelling for the canonical reason.
    pub const UnsupportedCriticalHeader: Self = Self::Sign1UnsupportedCriticalHeader;
    /// Compatibility spelling for the canonical reason.
    pub const UnprotectedSecurityHeader: Self = Self::Sign1UnprotectedHeaderNotAllowed;
    /// Compatibility spelling for the canonical reason.
    pub const Authentication: Self = Self::Sign1InvalidSignature;
    /// Compatibility spelling for the canonical reason.
    pub const SignatureEncoding: Self = Self::Sign1InvalidSignatureEncoding;
    /// Compatibility spelling for the canonical reason.
    pub const Key: Self = Self::KeyInvalidKeyMaterial;
    /// Compatibility spelling for the canonical reason.
    pub const InvalidKeyLength: Self = Self::KeyInvalidLength;
    /// Compatibility spelling for the canonical reason.
    pub const DetachedPayloadRequired: Self = Self::Mac0DetachedPayloadRequired;
    /// Compatibility spelling for the canonical reason.
    pub const InvalidTagLength: Self = Self::Mac0InvalidTagLength;
    /// Compatibility spelling for the canonical reason.
    pub const Profile: Self = Self::ContainerProfile;
    /// Compatibility spelling for the canonical reason.
    pub const CertificateValidation: Self = Self::ContainerCertificateValidation;
    /// Compatibility spelling for the canonical reason.
    pub const CertificateMismatch: Self = Self::ContainerCertificateMismatch;
    /// Compatibility spelling for the canonical reason.
    pub const ThumbprintLength: Self = Self::ContainerThumbprintLength;
    /// Compatibility spelling for the canonical reason.
    pub const SigningInput: Self = Self::ContainerSigningInput;
}

impl ::core::cmp::Eq for CoseSign1Options {}

impl Eq for CoseType {}
impl Eq for cose_type::Value {}
