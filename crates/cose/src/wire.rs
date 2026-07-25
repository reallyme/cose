// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Protobuf-ready COSE operation request and response adapters.
//!
//! This module deliberately does not run a service. It owns the stable binary
//! messages a Connect or FFI wrapper can forward without losing the exact
//! operation result or structured COSE error branch and reason code.

use buffa::{DecodeOptions, EnumValue, Message};
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::__buffa::oneof::cose_error::Error as CoseErrorBranchProto;
pub(crate) use reallyme_cose_proto::generated::proto::reallyme::cose::v1::__buffa::oneof::cose_operation_response_v2::Outcome as CoseOperationOutcomeV2;
pub(crate) use reallyme_cose_proto::generated::proto::reallyme::cose::v1::__buffa::oneof::cose_operation_result::Result as CoseOperationResultBranch;
use thiserror::Error;
use zeroize::Zeroizing;

/// Re-export of the generated protobuf boundary.
pub mod proto {
    pub use reallyme_cose_proto::generated::proto;
    pub use reallyme_cose_proto::generated::COSE_PROTO_PACKAGE;
}

pub use reallyme_cose_proto::generated::proto::reallyme::cose::v1::{
    __buffa::oneof::cose_algorithm_identifier, __buffa::oneof::cose_error as cose_error_proto,
    __buffa::oneof::cose_operation_request, __buffa::oneof::cose_operation_response_v2,
    __buffa::oneof::cose_operation_result, CoseAlgorithmIdentifier, CoseBackendError,
    CoseContentEncryptionAlgorithm, CoseError as CoseErrorProto, CoseErrorReason, CoseKemAlgorithm,
    CoseKeyAgreementAlgorithm, CoseKeyBytesRequest, CoseKeyBytesResult,
    CoseKeyFromPrivateBytesRequest, CoseKeyFromPublicBytesRequest, CoseMlKemDecryptRequest,
    CoseMlKemDecryptResult, CoseMlKemEncryptRequest, CoseMlKemEncryptResult, CoseMlKemMode,
    CoseMultikeyResult, CoseMultikeyToCoseKeyRequest, CoseOperationRequest,
    CoseOperationResponseV2, CoseOperationResult, CosePrimitiveError, CoseProviderError,
    CoseSign1CreateDetachedRequest, CoseSign1CreateRequest, CoseSign1CreateResult,
    CoseSign1Options, CoseSign1VerifyDetachedRequest, CoseSign1VerifyRequest,
    CoseSign1VerifyResult, CoseSignatureAlgorithm,
};

/// Maximum accepted protobuf message size at the COSE wire boundary.
///
/// The cap covers the largest supported detached-payload operation plus COSE
/// object and key material overhead. It is deliberately checked before protobuf
/// decode so hostile length-delimited fields cannot force unbounded allocation.
pub const MAX_COSE_PROTO_MESSAGE_BYTES: usize = 2_097_152;

/// Maximum caller-supplied COSE byte limit accepted by protobuf operations.
///
/// Native Rust APIs can opt into larger local policies directly. The protobuf
/// lane is intentionally capped to its message envelope so untrusted service,
/// FFI, and generated-SDK callers cannot widen boundary parsing beyond the
/// bytes this adapter already agreed to decode.
const COSE_PROTO_RECURSION_LIMIT: u32 = 64;
const COSE_PROTO_UNKNOWN_FIELD_LIMIT: usize = 0;

/// Maximum accepted generated ProtoJSON request size at the COSE wire boundary.
///
/// This leaves room for base64 expansion of the largest accepted protobuf
/// request plus generated field names and enum strings.
pub const MAX_COSE_PROTO_JSON_BYTES: usize = 3_145_728;

pub(crate) fn encode_protobuf<M: Message>(message: &M) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(message.encode_to_vec())
}

/// Decodes a bounded protobuf message from untrusted bytes.
///
/// # Errors
///
/// Returns [`CoseWireError`] when the input exceeds the message limit or is
/// malformed, recursively excessive, or otherwise rejected by Buffa.
pub(crate) fn decode_protobuf<M>(bytes: &[u8]) -> CoseWireResult<M>
where
    M: Message,
{
    decode_protobuf_with_limit(bytes, MAX_COSE_PROTO_MESSAGE_BYTES)
}

pub(crate) fn decode_protobuf_with_limit<M>(bytes: &[u8], max_bytes: usize) -> CoseWireResult<M>
where
    M: Message,
{
    if bytes.len() > max_bytes {
        return Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonResourceLimitExceeded,
        ));
    }

    DecodeOptions::new()
        .with_recursion_limit(COSE_PROTO_RECURSION_LIMIT)
        .with_max_message_size(max_bytes)
        // Executable crypto requests use an exact schema contract. Rejecting
        // unknown fields keeps binary protobuf semantics aligned with strict
        // ProtoJSON and prevents arbitrary length-delimited unknown values
        // from being retained in non-zeroizing generated storage.
        .with_unknown_field_limit(COSE_PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice(bytes)
        .map_err(|_| CoseWireError::primitive_internal(CoseErrorReason::CommonMalformedProtobuf))
}

pub(crate) fn decode_json<M: serde::de::DeserializeOwned + Message>(
    bytes: &[u8],
) -> CoseWireResult<M> {
    if bytes.len() > MAX_COSE_PROTO_JSON_BYTES {
        return Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonResourceLimitExceeded,
        ));
    }

    let message = serde_json::from_slice(bytes)
        .map_err(|_| CoseWireError::primitive_internal(CoseErrorReason::CommonMalformedJson))?;
    let encoded = encode_protobuf(&message);
    if encoded.len() > MAX_COSE_PROTO_MESSAGE_BYTES {
        return Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonResourceLimitExceeded,
        ));
    }
    Ok(message)
}

/// Decode a structured COSE error protobuf message.
///
/// # Errors
///
/// Returns a generated error response when the protobuf is malformed or its
/// branch and reason do not form a valid COSE error.
pub fn decode_cose_error(bytes: &[u8]) -> Result<CoseErrorProto, CoseOperationResponseV2> {
    let error = decode_protobuf::<CoseErrorProto>(bytes)
        .map_err(crate::operation_contract::response_v2::from_error)?;
    validate_cose_error_proto_wire(&error)
        .map_err(crate::operation_contract::response_v2::from_error)?;
    Ok(error)
}

/// Internal COSE wire-boundary error branch plus stable reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoseWireErrorBranch {
    Primitive,
    Provider,
    Backend,
}

/// Internal error preserving both the protobuf branch and exact reason.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("COSE wire boundary error")]
pub(crate) struct CoseWireError {
    branch: CoseWireErrorBranch,
    reason: CoseErrorReason,
}

impl CoseWireError {
    pub(crate) const fn branch(self) -> CoseWireErrorBranch {
        self.branch
    }

    pub(crate) const fn reason(self) -> CoseErrorReason {
        self.reason
    }

    pub(crate) const fn primitive_internal(reason: CoseErrorReason) -> Self {
        Self {
            branch: CoseWireErrorBranch::Primitive,
            reason,
        }
    }

    pub(crate) const fn provider_internal(reason: CoseErrorReason) -> Self {
        Self {
            branch: CoseWireErrorBranch::Provider,
            reason,
        }
    }

    pub(crate) const fn backend_internal(reason: CoseErrorReason) -> Self {
        Self {
            branch: CoseWireErrorBranch::Backend,
            reason,
        }
    }
}

pub(crate) type CoseWireResult<T> = Result<T, CoseWireError>;

/// Builds the structured `CoseError` protobuf message for a boundary error.
pub(crate) fn cose_error(error: CoseWireError) -> CoseErrorProto {
    let reason = EnumValue::from(error.reason());
    let branch = match error.branch() {
        CoseWireErrorBranch::Primitive => {
            CoseErrorBranchProto::Primitive(Box::new(CosePrimitiveError {
                reason,
                __buffa_unknown_fields: Default::default(),
            }))
        }
        CoseWireErrorBranch::Provider => {
            CoseErrorBranchProto::Provider(Box::new(CoseProviderError {
                reason,
                __buffa_unknown_fields: Default::default(),
            }))
        }
        CoseWireErrorBranch::Backend => CoseErrorBranchProto::Backend(Box::new(CoseBackendError {
            reason,
            __buffa_unknown_fields: Default::default(),
        })),
    };

    CoseErrorProto {
        error: Some(branch),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Decodes and executes the binary protobuf COSE operation entrypoint.
///
/// Native Rust SDK callers should keep using the ergonomic Rust APIs; service,
/// FFI, and generated-SDK wrappers can use this lane when they need one
/// mechanically testable protobuf boundary.
pub fn execute_operation_proto(request_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    crate::operation_contract::execute::execute_proto(request_bytes)
}

/// Decode and execute a generated ProtoJSON request using the fully
/// discriminated version-two binary response contract.
pub fn execute_operation_proto_json(request_json: &str) -> Zeroizing<Vec<u8>> {
    crate::operation_contract::execute::execute_proto_json(request_json)
}

/// Decode and validate an operation response.
///
/// Successful responses must carry the exact result oneof branch paired with
/// the request operation. Invalid, oversized, or mismatched responses return a
/// generated version-two backend error response rather than a generic Rust
/// error or a caller-input classification.
///
/// # Errors
///
/// Returns a generated [`CoseOperationResponseV2`] error outcome when the
/// response is malformed, oversized, lacks an outcome, contains invalid result
/// metadata, or does not match the request operation.
pub fn decode_operation_response(
    bytes: &[u8],
) -> Result<CoseOperationResponseV2, CoseOperationResponseV2> {
    crate::operation_contract::response_v2::decode(bytes)
}

/// Decode and validate a response for the request that produced it.
///
/// # Errors
///
/// Returns a generated [`CoseOperationResponseV2`] error outcome when the
/// response is invalid or its result branch does not match the request.
pub fn decode_operation_response_for_request(
    request: &CoseOperationRequest,
    bytes: &[u8],
) -> Result<CoseOperationResponseV2, CoseOperationResponseV2> {
    crate::operation_contract::response_v2::decode_for_request(request, bytes)
}

pub(crate) fn validate_cose_error_proto_wire(error: &CoseErrorProto) -> CoseWireResult<()> {
    let (branch, reason) = match error.error.as_ref() {
        Some(CoseErrorBranchProto::Primitive(error)) => {
            (CoseWireErrorBranch::Primitive, error.reason)
        }
        Some(CoseErrorBranchProto::Provider(error)) => {
            (CoseWireErrorBranch::Provider, error.reason)
        }
        Some(CoseErrorBranchProto::Backend(error)) => (CoseWireErrorBranch::Backend, error.reason),
        None => {
            return Err(malformed_error_envelope_error());
        }
    };

    match reason.as_known() {
        Some(CoseErrorReason::Unspecified) | None => Err(malformed_error_envelope_error()),
        Some(reason) if reason_is_valid_for_branch(branch, reason) => Ok(()),
        Some(_) => Err(malformed_error_envelope_error()),
    }
}

fn reason_is_valid_for_branch(branch: CoseWireErrorBranch, reason: CoseErrorReason) -> bool {
    match branch {
        CoseWireErrorBranch::Primitive => matches!(
            reason,
            CoseErrorReason::CommonCbor
                | CoseErrorReason::CommonInvalidFormat
                | CoseErrorReason::CommonResourceLimitExceeded
                | CoseErrorReason::CommonNonCanonicalCbor
                | CoseErrorReason::CommonUnexpectedCborTag
                | CoseErrorReason::CommonDuplicateMapLabel
                | CoseErrorReason::CommonMalformedProtobuf
                | CoseErrorReason::CommonMalformedJson
                | CoseErrorReason::CommonInvalidParameter
                | CoseErrorReason::CommonInvalidLength
                | CoseErrorReason::CommonInvalidEncoding
                | CoseErrorReason::Sign1MissingPayload
                | CoseErrorReason::Sign1MissingKid
                | CoseErrorReason::Sign1KeyNotResolved
                | CoseErrorReason::Sign1UnsupportedCriticalHeader
                | CoseErrorReason::Sign1UnprotectedHeaderNotAllowed
                | CoseErrorReason::Sign1InvalidSignature
                | CoseErrorReason::Sign1InvalidSignatureEncoding
                | CoseErrorReason::Sign1KidKeyMismatch
                | CoseErrorReason::Sign1MissingPrivateKey
                | CoseErrorReason::KeyMissingKeyMaterial
                | CoseErrorReason::KeyInvalidKeyMaterial
                | CoseErrorReason::MultikeyInvalidMultikey
                | CoseErrorReason::EncryptMissingCiphertext
                | CoseErrorReason::EncryptInvalidIv
                | CoseErrorReason::EncryptInvalidRecipient
                | CoseErrorReason::EncryptMissingEncapsulatedKey
                | CoseErrorReason::EncryptInvalidEncapsulatedKey
                | CoseErrorReason::EncryptAuthenticationFailed
                | CoseErrorReason::EncryptKeyUnwrapFailed
                | CoseErrorReason::EncryptKidMismatch
                | CoseErrorReason::EncryptMissingKid
                | CoseErrorReason::EncryptUnprotectedHeaderNotAllowed
        ),
        CoseWireErrorBranch::Provider => matches!(
            reason,
            CoseErrorReason::CommonUnsupportedAlgorithm | CoseErrorReason::ProviderUnavailable
        ),
        CoseWireErrorBranch::Backend => matches!(
            reason,
            CoseErrorReason::CommonResourceLimitExceeded
                | CoseErrorReason::CommonCryptoFailed
                | CoseErrorReason::BackendInternal
        ),
    }
}

const fn malformed_error_envelope_error() -> CoseWireError {
    CoseWireError::primitive_internal(CoseErrorReason::CommonMalformedProtobuf)
}
