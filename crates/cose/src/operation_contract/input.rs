// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conversion of generated request values into native domain inputs.

use crate::sign1::cose_type::CoseTypeExt;
use buffa::EnumValue;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::__buffa::oneof::cose_algorithm_identifier::Algorithm as CoseAlgorithmIdentifierBranch;
use reallyme_crypto::core::Algorithm;

use crate::algorithm::CoseSignatureAlgorithm as NativeCoseSignatureAlgorithm;
use crate::limits::{
    MAX_COSE_SIGN1_BYTES, MAX_COSE_X5CHAIN_CERTIFICATES, MAX_COSE_X5CHAIN_CERTIFICATE_BYTES,
    MAX_COSE_X5CHAIN_TOTAL_BYTES, MAX_DETACHED_PAYLOAD_BYTES,
};
use crate::wire::{
    CoseAlgorithmIdentifier, CoseContentEncryptionAlgorithm,
    CoseEc2PointEncoding as WireCoseEc2PointEncoding, CoseErrorReason, CoseKemAlgorithm,
    CoseKeyAgreementAlgorithm, CoseSign1Options,
    CoseSignatureAlgorithm as WireCoseSignatureAlgorithm, CoseType as WireCoseType, CoseWireError,
    CoseWireResult, CoseX5ChainHeaderPlacement as WireX5ChainHeaderPlacement,
    MAX_COSE_PROTO_MESSAGE_BYTES,
};
use crate::{
    CoseContentEncryptionAlgorithm as NativeCoseContentEncryptionAlgorithm, CoseEc2PointEncoding,
    CoseMlKemAlgorithm as NativeCoseMlKemAlgorithm, CosePolicy, CoseSign1EncodeOptions,
    X5ChainHeaderPlacement,
};

const MAX_WIRE_ALLOWED_SIGNATURE_ALGORITHMS: usize = 32;

pub(crate) fn encode_options_from_proto(
    options: Option<&mut CoseSign1Options>,
) -> CoseWireResult<CoseSign1EncodeOptions> {
    let Some(options) = options else {
        return Ok(CoseSign1EncodeOptions::default());
    };
    let x5chain_der =
        if let Some(chain) = options.x5chain.as_option_mut() {
            if chain.certificates_der.len() > MAX_COSE_X5CHAIN_CERTIFICATES {
                return Err(CoseWireError::primitive_internal(
                    CoseErrorReason::CommonResourceLimitExceeded,
                ));
            }
            let mut total = 0_usize;
            for certificate in &chain.certificates_der {
                total = total.checked_add(certificate.len()).ok_or(
                    CoseWireError::primitive_internal(CoseErrorReason::CommonResourceLimitExceeded),
                )?;
                if certificate.len() > MAX_COSE_X5CHAIN_CERTIFICATE_BYTES
                    || total > MAX_COSE_X5CHAIN_TOTAL_BYTES
                {
                    return Err(CoseWireError::primitive_internal(
                        CoseErrorReason::CommonResourceLimitExceeded,
                    ));
                }
            }
            core::mem::take(&mut chain.certificates_der)
        } else {
            Default::default()
        };
    let x5chain_header_placement = match options.x5chain_header_placement.as_known() {
        Some(WireX5ChainHeaderPlacement::Unspecified | WireX5ChainHeaderPlacement::Protected) => {
            X5ChainHeaderPlacement::Protected
        }
        Some(WireX5ChainHeaderPlacement::Unprotected) => X5ChainHeaderPlacement::Unprotected,
        None => {
            return Err(CoseWireError::primitive_internal(
                CoseErrorReason::CommonInvalidParameter,
            ));
        }
    };
    let mut result = CoseSign1EncodeOptions::new()
        .with_tag(options.tag)
        .with_max_cose_sign1_bytes(optional_limit_to_usize(
            options.max_cose_sign1_bytes,
            MAX_COSE_SIGN1_BYTES,
        )?)
        .with_guarded_x5chain(x5chain_der)
        .with_x5chain_header_placement(x5chain_header_placement);
    if let Some(limits) = options.limits.as_option() {
        result = result.with_max_cose_sign1_bytes(
            super::profile_input::bounded_length(
                limits.encoded_bytes,
                MAX_COSE_PROTO_MESSAGE_BYTES,
            )
            .map_err(|error| CoseWireError::from_reason(error.reason()))?,
        );
    }
    if let Some(value) = options
        .protected_type
        .as_option_mut()
        .and_then(|value| value.value.take())
    {
        value
            .validate()
            .map_err(|error| CoseWireError::from_reason(error.reason()))?;
        result = result.with_protected_type(value);
    }
    Ok(result)
}

pub(crate) fn policy_from_parts(
    max_cose_sign1_bytes: u64,
    max_detached_payload_bytes: u64,
    require_kid: bool,
    allowed_algorithms: &[EnumValue<WireCoseSignatureAlgorithm>],
    require_tagged_sign1: bool,
    expected_type: Option<&WireCoseType>,
) -> CoseWireResult<CosePolicy> {
    if allowed_algorithms.len() > MAX_WIRE_ALLOWED_SIGNATURE_ALGORITHMS {
        return Err(CoseWireError::primitive_internal(
            CoseErrorReason::CommonResourceLimitExceeded,
        ));
    }
    let mut allowed = Vec::with_capacity(allowed_algorithms.len());
    for candidate in allowed_algorithms {
        allowed.push(signature_algorithm_from_proto(*candidate)?);
    }
    let mut policy = CosePolicy::new()
        .with_require_kid(require_kid)
        .with_require_tagged_sign1(require_tagged_sign1)
        .with_max_cose_sign1_bytes(optional_limit_to_usize(
            max_cose_sign1_bytes,
            MAX_COSE_SIGN1_BYTES,
        )?)
        .with_max_detached_payload_bytes(optional_limit_to_usize(
            max_detached_payload_bytes,
            MAX_DETACHED_PAYLOAD_BYTES,
        )?);
    policy = if allowed.is_empty() {
        policy.allow_any_algorithm()
    } else {
        policy.with_allowed_cose_algorithms(allowed)
    };
    if let Some(expected_type) = expected_type {
        let value = expected_type
            .value
            .as_ref()
            .ok_or(CoseWireError::primitive_internal(
                CoseErrorReason::CommonInvalidParameter,
            ))?;
        let native_type = value.clone();
        native_type.validate().map_err(|_| {
            CoseWireError::primitive_internal(CoseErrorReason::CommonInvalidParameter)
        })?;
        policy = policy.with_expected_type(native_type);
    }
    Ok(policy)
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
    let algorithm = NativeCoseSignatureAlgorithm::try_from(value)
        .map_err(|error| CoseWireError::from_reason(error.reason()))?;
    algorithm
        .crypto_algorithm()
        .map_err(|error| CoseWireError::from_reason(error.reason()))?;
    Ok(algorithm)
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
    if value == WireCoseEc2PointEncoding::Unspecified {
        return Ok(None);
    }
    CoseEc2PointEncoding::try_from(value)
        .map(Some)
        .map_err(Into::into)
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
    if value == CoseKemAlgorithm::XWing768 {
        return Err(CoseWireError::provider_internal(
            CoseErrorReason::CommonUnsupportedAlgorithm,
        ));
    }
    NativeCoseMlKemAlgorithm::try_from(value).map_err(Into::into)
}

pub(crate) fn content_algorithm_from_proto(
    value: EnumValue<CoseContentEncryptionAlgorithm>,
) -> CoseWireResult<NativeCoseContentEncryptionAlgorithm> {
    NativeCoseContentEncryptionAlgorithm::try_from(value).map_err(Into::into)
}
