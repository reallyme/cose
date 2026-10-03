// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated-contract adapters for attached and detached COSE_Sign1 verification.

use zeroize::Zeroizing;

use crate::operation_contract::input::{policy_from_parts, signature_algorithm_from_proto};
use crate::operation_contract::map_failure::boundary_error_from_failure;
use crate::operation_contract::sign1::result;
use crate::sign1::types::{
    CoseSign1DetachedVerifyInput, CoseSign1KeyResolution, CoseSign1VerifyInput,
};
use crate::sign1::verify::{verify_cose_sign1, verify_detached_cose_sign1};
use crate::wire::{
    CoseOperationResult, CoseSign1VerifyDetachedRequest, CoseSign1VerifyRequest,
    CoseSignatureAlgorithm as WireSignatureAlgorithm, CoseWireResult,
};

pub(crate) fn attached_result(
    mut request: CoseSign1VerifyRequest,
) -> CoseWireResult<CoseOperationResult> {
    let cose_sign1 = Zeroizing::new(core::mem::take(&mut request.cose_sign1));
    let public_key = Zeroizing::new(core::mem::take(&mut request.public_key));
    let external_aad = Zeroizing::new(core::mem::take(&mut request.external_aad));
    let expected_kid = Zeroizing::new(core::mem::take(&mut request.expected_kid));
    let key_algorithm = expected_key_algorithm(request.public_key_algorithm)?;
    let policy = policy_from_parts(
        request.max_cose_sign1_bytes,
        request.max_detached_payload_bytes,
        request.require_kid,
        &request.allowed_algorithms,
        request.require_tagged_sign1,
        request.expected_type.as_option(),
    )?;
    let verified = verify_cose_sign1(
        CoseSign1VerifyInput::new(&cose_sign1, &external_aad, &policy),
        |algorithm, protected_kid| {
            resolve_request_key(
                algorithm,
                key_algorithm,
                protected_kid,
                &expected_kid,
                public_key,
            )
        },
    )
    .map_err(boundary_error_from_failure)?;
    result::verified_attached(verified)
}

pub(crate) fn detached_result(
    mut request: CoseSign1VerifyDetachedRequest,
) -> CoseWireResult<CoseOperationResult> {
    let cose_sign1 = Zeroizing::new(core::mem::take(&mut request.cose_sign1));
    let payload = Zeroizing::new(core::mem::take(&mut request.payload));
    let public_key = Zeroizing::new(core::mem::take(&mut request.public_key));
    let external_aad = Zeroizing::new(core::mem::take(&mut request.external_aad));
    let expected_kid = Zeroizing::new(core::mem::take(&mut request.expected_kid));
    let key_algorithm = expected_key_algorithm(request.public_key_algorithm)?;
    let policy = policy_from_parts(
        request.max_cose_sign1_bytes,
        request.max_detached_payload_bytes,
        request.require_kid,
        &request.allowed_algorithms,
        request.require_tagged_sign1,
        request.expected_type.as_option(),
    )?;
    let verified = verify_detached_cose_sign1(
        CoseSign1DetachedVerifyInput::new(&cose_sign1, &payload, &external_aad, &policy),
        |algorithm, protected_kid| {
            resolve_request_key(
                algorithm,
                key_algorithm,
                protected_kid,
                &expected_kid,
                public_key,
            )
        },
    )
    .map_err(boundary_error_from_failure)?;
    result::verified_detached(verified)
}

fn resolve_request_key(
    expected_algorithm: crate::CoseSignatureAlgorithm,
    key_algorithm: Option<crate::CoseSignatureAlgorithm>,
    protected_kid: &[u8],
    expected_kid: &[u8],
    public_key: Zeroizing<Vec<u8>>,
) -> CoseSign1KeyResolution {
    if key_algorithm.is_some_and(|configured| configured != expected_algorithm) {
        return CoseSign1KeyResolution::AlgorithmMismatch;
    }
    if expected_kid.is_empty()
        || reallyme_crypto::operations::constant_time::equal(protected_kid, expected_kid)
    {
        CoseSign1KeyResolution::Resolved(public_key)
    } else {
        CoseSign1KeyResolution::KidMismatch
    }
}

fn expected_key_algorithm(
    value: buffa::EnumValue<WireSignatureAlgorithm>,
) -> CoseWireResult<Option<crate::CoseSignatureAlgorithm>> {
    if value.as_known() == Some(WireSignatureAlgorithm::Unspecified) {
        return Ok(None);
    }
    signature_algorithm_from_proto(value).map(Some)
}
