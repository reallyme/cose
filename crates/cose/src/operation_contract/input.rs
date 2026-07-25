// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Conversion of generated request values into native domain inputs.

use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::__buffa::oneof::cose_algorithm_identifier::Algorithm as CoseAlgorithmIdentifierBranch;
use reallyme_crypto::core::Algorithm;

use crate::limits::{MAX_COSE_SIGN1_BYTES, MAX_DETACHED_PAYLOAD_BYTES};
use crate::wire::{
    CoseAlgorithmIdentifier, CoseContentEncryptionAlgorithm, CoseErrorReason, CoseKemAlgorithm,
    CoseKeyAgreementAlgorithm, CoseSign1Options, CoseSignatureAlgorithm, CoseWireError,
    CoseWireResult, MAX_COSE_PROTO_MESSAGE_BYTES,
};
use crate::{
    CoseContentEncryptionAlgorithm as NativeCoseContentEncryptionAlgorithm,
    CoseMlKemAlgorithm as NativeCoseMlKemAlgorithm, CosePolicy, CoseSign1EncodeOptions,
};

pub(crate) fn encode_options_from_proto(
    options: Option<&CoseSign1Options>,
) -> CoseWireResult<CoseSign1EncodeOptions> {
    let Some(options) = options else {
        return Ok(CoseSign1EncodeOptions::default());
    };
    Ok(CoseSign1EncodeOptions::new()
        .with_tag(options.tag)
        .with_max_cose_sign1_bytes(optional_limit_to_usize(
            options.max_cose_sign1_bytes,
            MAX_COSE_SIGN1_BYTES,
        )?))
}

pub(crate) fn policy_from_parts(
    max_cose_sign1_bytes: u64,
    max_detached_payload_bytes: u64,
    require_kid: bool,
    allowed_algorithms: &[EnumValue<CoseSignatureAlgorithm>],
) -> CoseWireResult<CosePolicy> {
    let mut allowed = Vec::with_capacity(allowed_algorithms.len());
    for candidate in allowed_algorithms {
        allowed.push(signature_algorithm_from_proto(*candidate)?);
    }
    Ok(CosePolicy::new()
        .with_require_kid(require_kid)
        .with_allowed_algorithms(allowed)
        .with_max_cose_sign1_bytes(optional_limit_to_usize(
            max_cose_sign1_bytes,
            MAX_COSE_SIGN1_BYTES,
        )?)
        .with_max_detached_payload_bytes(optional_limit_to_usize(
            max_detached_payload_bytes,
            MAX_DETACHED_PAYLOAD_BYTES,
        )?))
}

fn optional_limit_to_usize(value: u64, default: usize) -> CoseWireResult<usize> {
    if value == 0 {
        return Ok(default);
    }
    let limit = usize::try_from(value)
        .map_err(|_| CoseWireError::primitive_internal(CoseErrorReason::CommonInvalidLength))?;
    if limit > MAX_COSE_PROTO_MESSAGE_BYTES {
        return Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonResourceLimitExceeded,
        ));
    }
    Ok(limit)
}

pub(crate) fn signature_algorithm_from_proto(
    value: EnumValue<CoseSignatureAlgorithm>,
) -> CoseWireResult<Algorithm> {
    let algorithm = value.as_known().ok_or(CoseWireError::primitive_internal(
        CoseErrorReason::CommonInvalidParameter,
    ))?;
    match algorithm {
        CoseSignatureAlgorithm::Ed25519 => Ok(Algorithm::Ed25519),
        CoseSignatureAlgorithm::EcdsaP256Sha256 => Ok(Algorithm::P256),
        CoseSignatureAlgorithm::EcdsaP384Sha384 => Ok(Algorithm::P384),
        CoseSignatureAlgorithm::EcdsaP521Sha512 => Ok(Algorithm::P521),
        CoseSignatureAlgorithm::EcdsaSecp256k1Sha256 => Ok(Algorithm::Secp256k1),
        CoseSignatureAlgorithm::MlDsa44 => Ok(Algorithm::MlDsa44),
        CoseSignatureAlgorithm::MlDsa65 => Ok(Algorithm::MlDsa65),
        CoseSignatureAlgorithm::MlDsa87 => Ok(Algorithm::MlDsa87),
        CoseSignatureAlgorithm::Unspecified => Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonInvalidParameter,
        )),
    }
}

pub(crate) fn algorithm_identifier_from_proto(
    identifier: Option<&CoseAlgorithmIdentifier>,
) -> CoseWireResult<Algorithm> {
    let identifier = identifier.ok_or(CoseWireError::primitive_internal(
        CoseErrorReason::CommonInvalidParameter,
    ))?;
    match identifier.algorithm.as_ref() {
        Some(CoseAlgorithmIdentifierBranch::Signature(value)) => {
            signature_algorithm_from_proto(*value)
        }
        Some(CoseAlgorithmIdentifierBranch::KeyAgreement(value)) => {
            key_agreement_algorithm_from_proto(*value)
        }
        Some(CoseAlgorithmIdentifierBranch::Kem(value)) => kem_algorithm_from_proto(*value),
        None => Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonInvalidParameter,
        )),
    }
}

fn key_agreement_algorithm_from_proto(
    value: EnumValue<CoseKeyAgreementAlgorithm>,
) -> CoseWireResult<Algorithm> {
    let algorithm = value.as_known().ok_or(CoseWireError::primitive_internal(
        CoseErrorReason::CommonInvalidParameter,
    ))?;
    match algorithm {
        CoseKeyAgreementAlgorithm::X25519 => Ok(Algorithm::X25519),
        CoseKeyAgreementAlgorithm::Unspecified => Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonInvalidParameter,
        )),
    }
}

fn kem_algorithm_from_proto(value: EnumValue<CoseKemAlgorithm>) -> CoseWireResult<Algorithm> {
    let algorithm = value.as_known().ok_or(CoseWireError::primitive_internal(
        CoseErrorReason::CommonInvalidParameter,
    ))?;
    match algorithm {
        CoseKemAlgorithm::MlKem512 => Ok(Algorithm::MlKem512),
        CoseKemAlgorithm::MlKem768 => Ok(Algorithm::MlKem768),
        CoseKemAlgorithm::MlKem1024 => Ok(Algorithm::MlKem1024),
        CoseKemAlgorithm::XWing768 => Ok(Algorithm::XWing768),
        CoseKemAlgorithm::Unspecified => Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonInvalidParameter,
        )),
    }
}

pub(crate) fn ml_kem_algorithm_from_proto(
    value: EnumValue<CoseKemAlgorithm>,
) -> CoseWireResult<NativeCoseMlKemAlgorithm> {
    let algorithm = value.as_known().ok_or(CoseWireError::primitive_internal(
        CoseErrorReason::CommonInvalidParameter,
    ))?;
    match algorithm {
        CoseKemAlgorithm::MlKem512 => Ok(NativeCoseMlKemAlgorithm::MlKem512),
        CoseKemAlgorithm::MlKem768 => Ok(NativeCoseMlKemAlgorithm::MlKem768),
        CoseKemAlgorithm::MlKem1024 => Ok(NativeCoseMlKemAlgorithm::MlKem1024),
        CoseKemAlgorithm::Unspecified => Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonInvalidParameter,
        )),
        _ => Err(CoseWireError::provider_internal(
            CoseErrorReason::CommonUnsupportedAlgorithm,
        )),
    }
}

pub(crate) fn content_algorithm_from_proto(
    value: EnumValue<CoseContentEncryptionAlgorithm>,
) -> CoseWireResult<NativeCoseContentEncryptionAlgorithm> {
    let algorithm = value.as_known().ok_or(CoseWireError::primitive_internal(
        CoseErrorReason::CommonInvalidParameter,
    ))?;
    match algorithm {
        CoseContentEncryptionAlgorithm::Aes128Gcm => {
            Ok(NativeCoseContentEncryptionAlgorithm::Aes128Gcm)
        }
        CoseContentEncryptionAlgorithm::Aes192Gcm => {
            Ok(NativeCoseContentEncryptionAlgorithm::Aes192Gcm)
        }
        CoseContentEncryptionAlgorithm::Aes256Gcm => {
            Ok(NativeCoseContentEncryptionAlgorithm::Aes256Gcm)
        }
        CoseContentEncryptionAlgorithm::Unspecified => Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonInvalidParameter,
        )),
    }
}
