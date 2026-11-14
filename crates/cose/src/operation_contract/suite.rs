// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Suite inspection and public verification-key import from generated selectors.

use super::map_profile_failure::container as boundary_error_from_failure;
use super::profile_input::{copy, iso_suite, suite};
use crate::containers::{
    ContainerErrorReason as Reason, CryptoPeerKeyValidator, OptionalKeyPolicy, PeerKeyUsage,
};
use crate::iso18013::Iso18013CryptoVerifier;
use crate::wire::{
    cose_operation_result::Result as Branch, CoseOperationResult, CoseSuiteInfoRequest,
    CoseSuiteInfoResult, CoseVerificationKeyImportRequest, CoseWireResult, CoseWorkingKey,
};
use buffa::MessageField;
use zeroize::Zeroizing;

pub(crate) fn info(mut request: CoseSuiteInfoRequest) -> CoseWireResult<CoseOperationResult> {
    let value = request
        .suite
        .as_option()
        .ok_or(Reason::Algorithm)
        .map_err(|e| boundary_error_from_failure(e.into()))?;
    let (curve, builtin) = if let Ok(legacy) = iso_suite(value) {
        if request.require_iso_pair {
            suite(value).map_err(boundary_error_from_failure)?;
        }
        (legacy.curve(), legacy.has_builtin_provider())
    } else {
        let resolved = suite(value).map_err(boundary_error_from_failure)?;
        (resolved.curve(), true)
    };
    let message = CoseSuiteInfoResult {
        suite: MessageField::some(
            request
                .suite
                .take()
                .ok_or(Reason::Algorithm)
                .map_err(|e| boundary_error_from_failure(e.into()))?,
        ),
        signature_bytes: u64::try_from(
            curve
                .signature_length()
                .map_err(boundary_error_from_failure)?,
        )
        .map_err(|_| boundary_error_from_failure(Reason::Limit.into()))?,
        coordinate_bytes: u64::try_from(curve.coordinate_length().unwrap_or_default())
            .map_err(|_| boundary_error_from_failure(Reason::Limit.into()))?,
        okp_public_bytes: u64::try_from(curve.okp_public_length().unwrap_or_default())
            .map_err(|_| boundary_error_from_failure(Reason::Limit.into()))?,
        builtin_provider: builtin,
    };
    Ok(super::profile_result::operation(
        Branch::SignatureSuiteInfo(Box::new(message)),
    ))
}

pub(crate) fn import(
    mut request: CoseVerificationKeyImportRequest,
) -> CoseWireResult<CoseOperationResult> {
    if request.public_key.len() > crate::limits::MAX_COSE_KEY_BYTES {
        return Err(boundary_error_from_failure(Reason::Limit.into()));
    }
    if request.context_id.len() != super::profile_input::VERIFICATION_CONTEXT_BYTES {
        return Err(boundary_error_from_failure(Reason::Key.into()));
    }
    let value = request
        .suite
        .as_option()
        .ok_or(Reason::Algorithm)
        .map_err(|e| boundary_error_from_failure(e.into()))?;
    let public = if let Ok(legacy) = iso_suite(value) {
        if request.require_iso_pair {
            suite(value).map_err(boundary_error_from_failure)?;
        }
        let key = if request.public_key_is_cose {
            Iso18013CryptoVerifier::from_cose_key(legacy, &request.public_key)
        } else {
            Iso18013CryptoVerifier::new(
                legacy,
                core::mem::take(&mut request.public_key).into_zeroizing(),
            )
        }
        .map_err(|e| super::map_failure::boundary_error_from_failure(e.into()))?;
        copy(key.public_key()).map_err(boundary_error_from_failure)?
    } else {
        let resolved = suite(value).map_err(boundary_error_from_failure)?;
        if request.public_key_is_cose {
            let key = crate::containers::inspect_peer_key_operation(
                &request.public_key,
                PeerKeyUsage::Signature(resolved),
                OptionalKeyPolicy::Cose,
            )
            .map_err(boundary_error_from_failure)?
            .validate(&CryptoPeerKeyValidator)
            .map_err(boundary_error_from_failure)?;
            copy(key.public_view().public_material()).map_err(boundary_error_from_failure)?
        } else {
            use crate::containers::VerificationKey;
            let mut context = Zeroizing::new([0; super::profile_input::VERIFICATION_CONTEXT_BYTES]);
            context.copy_from_slice(&request.context_id);
            let key = crate::containers::CryptoVerificationKey::new(
                resolved,
                core::mem::take(&mut request.public_key).into_zeroizing(),
                *context,
            )
            .map_err(boundary_error_from_failure)?;
            copy(key.public_key()).map_err(boundary_error_from_failure)?
        }
    };
    let mut public = public;
    let message = CoseWorkingKey {
        suite: MessageField::some(
            request
                .suite
                .take()
                .ok_or(Reason::Algorithm)
                .map_err(|e| boundary_error_from_failure(e.into()))?,
        ),
        public_key: core::mem::take(&mut *public).into(),
        context_id: core::mem::take(&mut request.context_id),
    };
    Ok(super::profile_result::operation(
        Branch::VerificationKeyImport(Box::new(message)),
    ))
}

pub(crate) fn contract_info() -> CoseWireResult<CoseOperationResult> {
    use reallyme_cose_proto::generated::proto::reallyme::cose::v1::{
        CoseContractInfoResult, CoseNamedConstant,
    };
    let mut constants = Vec::new();
    constants
        .try_reserve_exact(crate::generated_contract::CONSTANTS.len())
        .map_err(|_| boundary_error_from_failure(Reason::Limit.into()))?;
    for &(constant, value) in crate::generated_contract::CONSTANTS {
        constants.push(CoseNamedConstant {
            constant: constant.into(),
            value,
        });
    }
    Ok(super::profile_result::operation(Branch::ContractInfo(
        Box::new(CoseContractInfoResult {
            constants: constants.into(),
        }),
    )))
}
