// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, reason, success};
use crate::api::contract::{
    __buffa::oneof::{cose_operation_request::Operation, cose_operation_result::Result as Branch},
    CoseErrorReason, CoseSign1SignatureStructureRequest,
};
use crate::sign1::build_sign1_signature_structure;
use crate::CoseError;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn signature_structure_contract_matches_native_bytes_and_fixed_budget_failures(
) -> Result<(), CoseError> {
    let protected = [0xa2, 0x04, 0x41, 0xab, 0x01, 0x26];
    let expected = build_sign1_signature_structure(&protected, &[], b"payload", usize::MAX)?;
    let length = u64::try_from(expected.len()).map_err(|_| CoseError::ResourceLimitExceeded)?;
    for budget in [
        0,
        length
            .checked_sub(1)
            .ok_or(CoseError::ResourceLimitExceeded)?,
        length,
        u64::MAX,
    ] {
        let request = CoseSign1SignatureStructureRequest::default()
            .with_protected(protected.to_vec())
            .with_payload(b"payload".to_vec())
            .with_max_output_bytes(budget);
        let response = codec_parity(Operation::Sign1SignatureStructure(Box::new(request)))?;
        if budget < length {
            assert_eq!(
                reason(&response),
                CoseErrorReason::CommonResourceLimitExceeded
            );
        } else {
            let Branch::Sign1SignatureStructure(result) = &success(response) else {
                return Err(CoseError::InvalidFormat);
            };
            assert_eq!(result.signature_structure.as_slice(), expected.as_slice());
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn signature_structure_contract_supports_large_opaque_fields() -> Result<(), CoseError> {
    let protected = vec![0x5a; 786_432];
    let payload = vec![0x42; 1_048_577];
    let expected = build_sign1_signature_structure(&protected, &[], &payload, 2_097_152)?;
    let request = CoseSign1SignatureStructureRequest::default()
        .with_protected(protected)
        .with_payload(payload)
        .with_max_output_bytes(2_097_152_u64);
    let response = codec_parity(Operation::Sign1SignatureStructure(Box::new(request)))?;
    let Branch::Sign1SignatureStructure(result) = &success(response) else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(result.signature_structure.as_slice(), expected.as_slice());
    Ok(())
}
