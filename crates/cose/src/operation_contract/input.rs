// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conversion of generated request values into native domain inputs.

use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::__buffa::oneof::cose_algorithm_identifier::Algorithm as CoseAlgorithmIdentifierBranch;
use reallyme_crypto::core::Algorithm;

use crate::algorithm::CoseSignatureAlgorithm as NativeCoseSignatureAlgorithm;
use crate::limits::{MAX_COSE_SIGN1_BYTES, MAX_DETACHED_PAYLOAD_BYTES};
use crate::wire::{
    CoseAlgorithmIdentifier, CoseContentEncryptionAlgorithm,
    CoseEc2PointEncoding as WireCoseEc2PointEncoding, CoseErrorReason, CoseKemAlgorithm,
    CoseKeyAgreementAlgorithm, CoseSign1Options,
    CoseSignatureAlgorithm as WireCoseSignatureAlgorithm, CoseWireError, CoseWireResult,
    MAX_COSE_PROTO_MESSAGE_BYTES,
};
use crate::{
    CoseContentEncryptionAlgorithm as NativeCoseContentEncryptionAlgorithm, CoseEc2PointEncoding,
    CoseMlKemAlgorithm as NativeCoseMlKemAlgorithm, CosePolicy, CoseSign1EncodeOptions,
};

pub(crate) fn encode_options_from_proto(
    options: Option<&CoseSign1Options>,
) -> CoseWireResult<CoseSign1EncodeOptions> {
    let Some(options) = options else {
        return Ok(CoseSign1EncodeOptions::default());
    };
    let x5chain_der = options
        .x5chain
        .as_option()
        .map(|chain| chain.certificates_der.clone())
        .unwrap_or_default();
    Ok(CoseSign1EncodeOptions::new()
        .with_tag(options.tag)
        .with_max_cose_sign1_bytes(optional_limit_to_usize(
            options.max_cose_sign1_bytes,
            MAX_COSE_SIGN1_BYTES,
        )?)
        .with_x5chain_der(x5chain_der))
}

pub(crate) fn policy_from_parts(
    max_cose_sign1_bytes: u64,
    max_detached_payload_bytes: u64,
    require_kid: bool,
    allowed_algorithms: &[EnumValue<WireCoseSignatureAlgorithm>],
) -> CoseWireResult<CosePolicy> {
    let mut allowed = Vec::with_capacity(allowed_algorithms.len());
    for candidate in allowed_algorithms {
        allowed.push(signature_algorithm_from_proto(*candidate)?);
    }
    Ok(CosePolicy::new()
        .with_require_kid(require_kid)
        .with_allowed_cose_algorithms(allowed)
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
    value: EnumValue<WireCoseSignatureAlgorithm>,
) -> CoseWireResult<NativeCoseSignatureAlgorithm> {
    let algorithm = value.as_known().ok_or(CoseWireError::primitive_internal(
        CoseErrorReason::CommonInvalidParameter,
    ))?;
    match algorithm {
        WireCoseSignatureAlgorithm::Ed25519 => Ok(NativeCoseSignatureAlgorithm::Ed25519),
        WireCoseSignatureAlgorithm::EcdsaP256Sha256 | WireCoseSignatureAlgorithm::Esp256 => {
            Ok(NativeCoseSignatureAlgorithm::Esp256)
        }
        WireCoseSignatureAlgorithm::Es256 => Ok(NativeCoseSignatureAlgorithm::Es256),
        WireCoseSignatureAlgorithm::EcdsaP384Sha384 | WireCoseSignatureAlgorithm::Esp384 => {
            Ok(NativeCoseSignatureAlgorithm::Esp384)
        }
        WireCoseSignatureAlgorithm::EcdsaP521Sha512 | WireCoseSignatureAlgorithm::Esp512 => {
            Ok(NativeCoseSignatureAlgorithm::Esp512)
        }
        WireCoseSignatureAlgorithm::EcdsaSecp256k1Sha256 => {
            Ok(NativeCoseSignatureAlgorithm::Es256K)
        }
        WireCoseSignatureAlgorithm::MlDsa44 => Ok(NativeCoseSignatureAlgorithm::MlDsa44),
        WireCoseSignatureAlgorithm::MlDsa65 => Ok(NativeCoseSignatureAlgorithm::MlDsa65),
        WireCoseSignatureAlgorithm::MlDsa87 => Ok(NativeCoseSignatureAlgorithm::MlDsa87),
        WireCoseSignatureAlgorithm::Unspecified => Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonInvalidParameter,
        )),
    }
}

pub(crate) enum KeyAlgorithmInput {
    Signature(NativeCoseSignatureAlgorithm),
    Crypto(Algorithm),
}

impl KeyAlgorithmInput {
    pub(crate) fn supports_ec2_point_encoding(&self) -> bool {
        matches!(
            self,
            Self::Signature(
                NativeCoseSignatureAlgorithm::Es256
                    | NativeCoseSignatureAlgorithm::Esp256
                    | NativeCoseSignatureAlgorithm::Esp384
                    | NativeCoseSignatureAlgorithm::Esp512
                    | NativeCoseSignatureAlgorithm::Es256K,
            ) | Self::Crypto(
                Algorithm::P256 | Algorithm::P384 | Algorithm::P521 | Algorithm::Secp256k1,
            )
        )
    }
}

pub(crate) fn ec2_point_encoding_from_proto(
    value: EnumValue<WireCoseEc2PointEncoding>,
) -> CoseWireResult<Option<CoseEc2PointEncoding>> {
    match value.as_known() {
        Some(WireCoseEc2PointEncoding::Unspecified) => Ok(None),
        Some(WireCoseEc2PointEncoding::Compressed) => Ok(Some(CoseEc2PointEncoding::Compressed)),
        Some(WireCoseEc2PointEncoding::FullCoordinates) => {
            Ok(Some(CoseEc2PointEncoding::FullCoordinates))
        }
        None => Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonInvalidParameter,
        )),
    }
}

pub(crate) fn validate_ec2_point_encoding(
    algorithm: &KeyAlgorithmInput,
    encoding: Option<CoseEc2PointEncoding>,
) -> CoseWireResult<Option<CoseEc2PointEncoding>> {
    if encoding.is_some() && !algorithm.supports_ec2_point_encoding() {
        return Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonInvalidParameter,
        ));
    }
    Ok(encoding)
}

pub(crate) fn key_algorithm_identifier_from_proto(
    identifier: Option<&CoseAlgorithmIdentifier>,
) -> CoseWireResult<KeyAlgorithmInput> {
    let identifier = identifier.ok_or(CoseWireError::primitive_internal(
        CoseErrorReason::CommonInvalidParameter,
    ))?;
    match identifier.algorithm.as_ref() {
        Some(CoseAlgorithmIdentifierBranch::Signature(value)) => {
            signature_algorithm_from_proto(*value).map(KeyAlgorithmInput::Signature)
        }
        Some(CoseAlgorithmIdentifierBranch::KeyAgreement(value)) => {
            key_agreement_algorithm_from_proto(*value).map(KeyAlgorithmInput::Crypto)
        }
        Some(CoseAlgorithmIdentifierBranch::Kem(value)) => {
            kem_algorithm_from_proto(*value).map(KeyAlgorithmInput::Crypto)
        }
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
