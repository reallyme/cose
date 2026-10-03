// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::Message;
use reallyme_cose::wire::{
    CoseKeyBytesResult, CoseKeyFromPublicBytesRequest, CoseSign1CreateResult,
    CoseSign1VerifyResult, CoseSignatureAlgorithm,
};
use reallyme_cose::{
    cose_key_from_slice, cose_key_signature_algorithm,
    CoseSignatureAlgorithm as NativeSignatureAlgorithm,
};

use crate::support::{gen_p256, sample_payload, test_kid, OperationOutputStatus};

use super::{
    execute_cose_sign1_create_request, execute_cose_sign1_verify_request, execute_operation_bytes,
    operation_request, sign1_create_request, sign1_verify_request, signature_identifier,
    signature_value, CoseOperationRequestBranch,
};

#[test]
fn es256_wire_contract_preserves_the_exact_registration() {
    let key = gen_p256();
    let key_request = CoseKeyFromPublicBytesRequest {
        algorithm: signature_identifier(CoseSignatureAlgorithm::Es256),
        public_key: key.public.clone(),
        ec2_point_encoding: Default::default(),
        __buffa_unknown_fields: Default::default(),
    };
    let key_output = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::KeyFromPublicBytes(Box::new(
            key_request,
        )))
        .encode_to_vec(),
    );
    assert_eq!(key_output.status(), OperationOutputStatus::Result);
    let key_result = CoseKeyBytesResult::decode_from_slice(key_output.bytes())
        .expect("ES256 COSE_Key result must decode");
    assert!(key_result.has_signature_algorithm);
    assert_eq!(
        key_result.signature_algorithm.as_known(),
        Some(CoseSignatureAlgorithm::Es256),
    );
    let parsed_key =
        cose_key_from_slice(&key_result.key_bytes).expect("wire-produced ES256 key must parse");
    assert_eq!(
        cose_key_signature_algorithm(&parsed_key).expect("ES256 metadata must validate"),
        Some(NativeSignatureAlgorithm::Es256),
    );

    let legacy_request = CoseKeyFromPublicBytesRequest {
        algorithm: signature_identifier(CoseSignatureAlgorithm::EcdsaP256Sha256),
        public_key: key.public.clone(),
        ec2_point_encoding: Default::default(),
        __buffa_unknown_fields: Default::default(),
    };
    let legacy_output = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::KeyFromPublicBytes(Box::new(
            legacy_request,
        )))
        .encode_to_vec(),
    );
    let legacy_result = CoseKeyBytesResult::decode_from_slice(legacy_output.bytes())
        .expect("legacy P-256 result must decode");
    assert_eq!(
        legacy_result.signature_algorithm.as_known(),
        Some(CoseSignatureAlgorithm::Esp256),
    );
    let create = sign1_create_request(
        CoseSignatureAlgorithm::Es256,
        sample_payload(),
        key.private,
        test_kid().to_vec(),
        true,
    );
    let signed = execute_cose_sign1_create_request(&create.encode_to_vec());
    assert_eq!(signed.status(), OperationOutputStatus::Result);
    let create_result = CoseSign1CreateResult::decode_from_slice(signed.bytes())
        .expect("ES256 create result must decode");

    let mut verify = sign1_verify_request(create_result.cose_sign1.clone(), key.public, true);
    verify.allowed_algorithms = vec![signature_value(CoseSignatureAlgorithm::Es256)];
    verify.public_key_algorithm = signature_value(CoseSignatureAlgorithm::Es256);
    let verified = execute_cose_sign1_verify_request(&verify.encode_to_vec());
    assert_eq!(verified.status(), OperationOutputStatus::Result);
    let verify_result = CoseSign1VerifyResult::decode_from_slice(verified.bytes())
        .expect("ES256 verify result must decode");
    assert_eq!(
        verify_result.algorithm.as_known(),
        Some(CoseSignatureAlgorithm::EcdsaP256Sha256),
    );
    assert!(verify_result.has_exact_signature_algorithm);
    assert_eq!(
        verify_result.exact_signature_algorithm.as_known(),
        Some(CoseSignatureAlgorithm::Es256),
    );
}
