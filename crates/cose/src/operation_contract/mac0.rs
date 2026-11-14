// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Detached MAC verification through the generated operation contract.

use super::map_profile_failure::mac0 as boundary_error_from_failure;
use super::providers::OperationProviders;
use crate::mac0::{
    verify_mac0_operation, CoseMac0Error, CoseMac0ErrorReason as Reason, CoseMac0Limits,
    CoseMac0VerifyRequest as Input, CoseMacAlgorithm, CoseMacKey,
};
use crate::wire::{
    cose_operation_result::Result as Branch, CoseKeySource, CoseMac0VerifyRequest,
    CoseMac0VerifyResult, CoseMacAlgorithm as Algorithm, CoseOperationResult, CoseWireResult,
};
use buffa::EnumValue;

use crate::generated_contract::values::MAX_ALLOWLIST_ENTRIES as MAX_ALGORITHMS;

fn algorithm(value: EnumValue<Algorithm>) -> Result<CoseMacAlgorithm, CoseMac0Error> {
    CoseMacAlgorithm::try_from(value)
}

fn limits(request: &CoseMac0VerifyRequest) -> Result<CoseMac0Limits, CoseMac0Error> {
    let Some(limits) = request.limits.as_option() else {
        return Ok(CoseMac0Limits::default());
    };
    let length = |value, maximum| -> Result<usize, CoseMac0Error> {
        super::profile_input::bounded_length(value, maximum)
            .map_err(|_| Reason::ResourceLimitExceeded.into())
    };
    Ok(CoseMac0Limits {
        encoded_bytes: length(limits.encoded_bytes, crate::limits::MAX_COSE_MAC0_BYTES)?,
        payload_bytes: length(
            limits.payload_bytes,
            crate::limits::MAX_DETACHED_PAYLOAD_BYTES,
        )?,
        external_aad_bytes: length(
            limits.external_aad_bytes,
            crate::limits::MAX_MAC0_EXTERNAL_AAD_BYTES,
        )?,
    })
}

pub(crate) fn verify(
    mut request: CoseMac0VerifyRequest,
    providers: &dyn OperationProviders,
) -> CoseWireResult<CoseOperationResult> {
    let key_handle = crate::operation_contract::providers::capability_handle(
        request.capability.as_option(),
        crate::api::contract::CoseProviderKind::MacVerifier,
    )?;
    let limits = limits(&request).map_err(boundary_error_from_failure)?;
    if request.allowed_algorithms.len() > MAX_ALGORITHMS {
        return Err(boundary_error_from_failure(
            Reason::ResourceLimitExceeded.into(),
        ));
    }
    let mut allowed = Vec::new();
    allowed
        .try_reserve_exact(request.allowed_algorithms.len())
        .map_err(|_| boundary_error_from_failure(Reason::ResourceLimitExceeded.into()))?;
    for value in &request.allowed_algorithms {
        allowed.push(algorithm(*value).map_err(boundary_error_from_failure)?);
    }
    let key_algorithm = algorithm(request.key_algorithm).map_err(boundary_error_from_failure)?;
    let owned;
    let key: &dyn crate::mac0::CoseMacVerifier = match request.key_source.as_known() {
        Some(CoseKeySource::Direct) if key_handle == 0 => {
            owned = CoseMacKey::new(
                key_algorithm,
                core::mem::take(&mut request.key).into_zeroizing(),
            )
            .map_err(boundary_error_from_failure)?;
            &owned
        }
        Some(CoseKeySource::Provider) if key_handle != 0 && request.key.is_empty() => {
            let key = providers.mac_verifier(key_handle).map_err(|error| {
                let reason = match error.reason() {
                    crate::containers::ContainerErrorReason::Provider => {
                        Reason::ProviderUnavailable
                    }
                    crate::containers::ContainerErrorReason::Algorithm => {
                        Reason::UnsupportedAlgorithm
                    }
                    crate::containers::ContainerErrorReason::Key => Reason::KeyAlgorithmMismatch,
                    crate::containers::ContainerErrorReason::Limit => Reason::ResourceLimitExceeded,
                    _ => Reason::BackendFailure,
                };
                boundary_error_from_failure(reason.into())
            })?;
            if key.algorithm() != key_algorithm {
                return Err(boundary_error_from_failure(
                    Reason::KeyAlgorithmMismatch.into(),
                ));
            }
            key
        }
        _ => return Err(boundary_error_from_failure(Reason::InvalidStructure.into())),
    };
    let output = verify_mac0_operation(
        Input {
            encoded: &request.encoded,
            detached_payload: &request.detached_payload,
            external_aad: &request.external_aad,
            allowed_algorithms: &allowed,
            limits,
        },
        key,
    )
    .map_err(boundary_error_from_failure)?;
    let mut protected = super::profile_input::copy(output.protected_header_bytes())
        .map_err(|_| boundary_error_from_failure(Reason::ResourceLimitExceeded.into()))?;
    let mut kid = super::profile_input::copy(output.protected_key_id().unwrap_or_default())
        .map_err(|_| boundary_error_from_failure(Reason::ResourceLimitExceeded.into()))?;
    let message = CoseMac0VerifyResult {
        algorithm: EnumValue::from(
            i32::try_from(output.algorithm().cose_id())
                .map_err(|_| boundary_error_from_failure(Reason::BackendFailure.into()))?,
        ),
        protected_headers: core::mem::take(&mut *protected).into(),
        protected_kid: output
            .protected_key_id()
            .map(|_| core::mem::take(&mut *kid).into()),
    };
    Ok(super::profile_result::operation(
        Branch::Mac0VerifyDetached(Box::new(message)),
    ))
}
