// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use buffa::{EnumValue, Message};
use reallyme_cose::wire::cose_error_proto;
use reallyme_cose::wire::cose_operation_request::Operation;
use reallyme_cose::wire::{
    decode_cose_error, execute_operation_proto, execute_operation_proto_json, CoseErrorReason,
    CoseOperationRequest, CoseSign1CreateDetachedRequest, CoseSign1CreateRequest,
    CoseSign1CreateResult, CoseSign1Options, CoseSign1VerifyDetachedRequest,
    CoseSign1VerifyRequest, CoseSign1VerifyResult, CoseSignatureAlgorithm,
};
use reallyme_cose::{
    cose_sign1_detached_with_options_and_external_aad, cose_sign1_with_options_and_external_aad,
    cose_verify1_detached_with_policy_and_external_aad, cose_verify1_with_policy_and_external_aad,
    Algorithm, CoseError, CosePolicy, CoseSign1EncodeOptions,
};
use zeroize::Zeroizing;

use super::support::{
    decode_operation_output, gen_ed25519, sample_payload, test_kid, OperationOutputStatus,
};

const EXTERNAL_AAD: &[u8] = b"reallyme-cose/sign1/external-aad";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorBranch {
    Primitive,
    Provider,
    Backend,
}

#[test]
fn sign1_operations_match_native_binary_and_proto_json() {
    let mut fixture = gen_ed25519();
    let public_key = Zeroizing::new(core::mem::take(&mut fixture.public));
    let private_key = Zeroizing::new(core::mem::take(&mut fixture.private));
    let payload = Zeroizing::new(sample_payload());
    let options = CoseSign1EncodeOptions::tagged();

    let native_attached = cose_sign1_with_options_and_external_aad(
        fixture.alg,
        &payload,
        &private_key,
        Some(test_kid()),
        EXTERNAL_AAD,
        options,
    )
    .expect("native attached signing must succeed");
    let wire_attached = execute_create(Operation::Sign1Create(Box::new(create_request(
        &payload,
        &private_key,
        true,
    ))));
    assert_eq!(wire_attached.as_slice(), native_attached.as_slice());

    let native_detached = cose_sign1_detached_with_options_and_external_aad(
        fixture.alg,
        &payload,
        &private_key,
        Some(test_kid()),
        EXTERNAL_AAD,
        options,
    )
    .expect("native detached signing must succeed");
    let wire_detached = execute_create(Operation::Sign1CreateDetached(Box::new(
        create_detached_request(&payload, &private_key, true),
    )));
    assert_eq!(wire_detached.as_slice(), native_detached.as_slice());

    let policy = verification_policy(vec![Algorithm::Ed25519]);
    let native_verified = cose_verify1_with_policy_and_external_aad(
        &native_attached,
        EXTERNAL_AAD,
        &policy,
        |_, _| Some(public_key.to_vec()),
    )
    .expect("native attached verification must succeed");
    let wire_verified = execute_verify(Operation::Sign1Verify(Box::new(verify_request(
        &native_attached,
        &public_key,
        test_kid(),
        vec![CoseSignatureAlgorithm::Ed25519],
    ))));
    assert_eq!(wire_verified.payload, native_verified.payload.as_slice());
    assert_eq!(
        wire_verified.algorithm.as_known(),
        Some(CoseSignatureAlgorithm::Ed25519)
    );
    assert_eq!(wire_verified.kid, native_verified.kid.as_slice());

    let native_detached_verified = cose_verify1_detached_with_policy_and_external_aad(
        &native_detached,
        &payload,
        EXTERNAL_AAD,
        &policy,
        |_, _| Some(public_key.to_vec()),
    )
    .expect("native detached verification must succeed");
    let wire_detached_verified = execute_verify(Operation::Sign1VerifyDetached(Box::new(
        verify_detached_request(
            &native_detached,
            &payload,
            &public_key,
            test_kid(),
            vec![CoseSignatureAlgorithm::Ed25519],
        ),
    )));
    assert!(wire_detached_verified.payload.is_empty());
    assert_eq!(
        wire_detached_verified.algorithm.as_known(),
        Some(CoseSignatureAlgorithm::Ed25519)
    );
    assert_eq!(
        wire_detached_verified.kid,
        native_detached_verified.kid.as_slice()
    );
}

#[test]
fn sign1_failures_preserve_native_and_exact_wire_semantics() {
    let mut fixture = gen_ed25519();
    let public_key = Zeroizing::new(core::mem::take(&mut fixture.public));
    let private_key = Zeroizing::new(core::mem::take(&mut fixture.private));
    let payload = Zeroizing::new(sample_payload());
    let invalid_private_key = Zeroizing::new(vec![0_u8; 31]);

    assert_native_error(
        cose_sign1_with_options_and_external_aad(
            fixture.alg,
            &payload,
            &invalid_private_key,
            Some(test_kid()),
            EXTERNAL_AAD,
            CoseSign1EncodeOptions::tagged(),
        ),
        CoseError::InvalidKeyMaterial,
    );
    assert_error(
        Operation::Sign1Create(Box::new(create_request(
            &payload,
            &invalid_private_key,
            true,
        ))),
        ErrorBranch::Primitive,
        CoseErrorReason::KeyInvalidKeyMaterial,
    );

    let detached = cose_sign1_detached_with_options_and_external_aad(
        fixture.alg,
        &payload,
        &private_key,
        Some(test_kid()),
        EXTERNAL_AAD,
        CoseSign1EncodeOptions::tagged(),
    )
    .expect("detached fixture must sign");
    let policy = verification_policy(vec![Algorithm::Ed25519]);
    assert_native_error(
        cose_verify1_with_policy_and_external_aad(&detached, EXTERNAL_AAD, &policy, |_, _| {
            Some(public_key.to_vec())
        }),
        CoseError::MissingPayload,
    );
    assert_error(
        Operation::Sign1Verify(Box::new(verify_request(
            &detached,
            &public_key,
            test_kid(),
            vec![CoseSignatureAlgorithm::Ed25519],
        ))),
        ErrorBranch::Primitive,
        CoseErrorReason::Sign1MissingPayload,
    );

    let wrong_payload = Zeroizing::new(b"wrong detached payload".to_vec());
    assert_native_error(
        cose_verify1_detached_with_policy_and_external_aad(
            &detached,
            &wrong_payload,
            EXTERNAL_AAD,
            &policy,
            |_, _| Some(public_key.to_vec()),
        ),
        CoseError::InvalidSignature,
    );
    assert_error(
        Operation::Sign1VerifyDetached(Box::new(verify_detached_request(
            &detached,
            &wrong_payload,
            &public_key,
            test_kid(),
            vec![CoseSignatureAlgorithm::Ed25519],
        ))),
        ErrorBranch::Primitive,
        CoseErrorReason::Sign1InvalidSignature,
    );

    assert_error(
        Operation::Sign1VerifyDetached(Box::new(verify_detached_request(
            &detached,
            &payload,
            &public_key,
            b"different-kid",
            vec![CoseSignatureAlgorithm::Ed25519],
        ))),
        ErrorBranch::Primitive,
        CoseErrorReason::Sign1KidKeyMismatch,
    );

    let disallowed_policy = verification_policy(vec![Algorithm::P256]);
    assert_native_error(
        cose_verify1_detached_with_policy_and_external_aad(
            &detached,
            &payload,
            EXTERNAL_AAD,
            &disallowed_policy,
            |_, _| Some(public_key.to_vec()),
        ),
        CoseError::UnsupportedAlgorithm,
    );
    assert_error(
        Operation::Sign1VerifyDetached(Box::new(verify_detached_request(
            &detached,
            &payload,
            &public_key,
            test_kid(),
            vec![CoseSignatureAlgorithm::EcdsaP256Sha256],
        ))),
        ErrorBranch::Provider,
        CoseErrorReason::CommonUnsupportedAlgorithm,
    );
}

fn create_request(payload: &[u8], private_key: &[u8], tagged: bool) -> CoseSign1CreateRequest {
    CoseSign1CreateRequest {
        algorithm: EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        payload: payload.to_vec(),
        private_key: private_key.to_vec(),
        kid: test_kid().to_vec(),
        has_kid: true,
        options: sign_options(tagged),
        external_aad: EXTERNAL_AAD.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn create_detached_request(
    payload: &[u8],
    private_key: &[u8],
    tagged: bool,
) -> CoseSign1CreateDetachedRequest {
    CoseSign1CreateDetachedRequest {
        algorithm: EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        payload: payload.to_vec(),
        private_key: private_key.to_vec(),
        kid: test_kid().to_vec(),
        has_kid: true,
        options: sign_options(tagged),
        external_aad: EXTERNAL_AAD.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn sign_options(
    tagged: bool,
) -> buffa::MessageField<CoseSign1Options, buffa::Inline<CoseSign1Options>> {
    buffa::MessageField::some(CoseSign1Options {
        tag: tagged,
        max_cose_sign1_bytes: 0,
        __buffa_unknown_fields: Default::default(),
    })
}

fn verify_request(
    cose_sign1: &[u8],
    public_key: &[u8],
    expected_kid: &[u8],
    allowed_algorithms: Vec<CoseSignatureAlgorithm>,
) -> CoseSign1VerifyRequest {
    CoseSign1VerifyRequest {
        cose_sign1: cose_sign1.to_vec(),
        public_key: public_key.to_vec(),
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid: true,
        allowed_algorithms: allowed_algorithms
            .into_iter()
            .map(EnumValue::from)
            .collect(),
        external_aad: EXTERNAL_AAD.to_vec(),
        expected_kid: expected_kid.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn verify_detached_request(
    cose_sign1: &[u8],
    payload: &[u8],
    public_key: &[u8],
    expected_kid: &[u8],
    allowed_algorithms: Vec<CoseSignatureAlgorithm>,
) -> CoseSign1VerifyDetachedRequest {
    CoseSign1VerifyDetachedRequest {
        cose_sign1: cose_sign1.to_vec(),
        payload: payload.to_vec(),
        public_key: public_key.to_vec(),
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid: true,
        allowed_algorithms: allowed_algorithms
            .into_iter()
            .map(EnumValue::from)
            .collect(),
        external_aad: EXTERNAL_AAD.to_vec(),
        expected_kid: expected_kid.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn verification_policy(allowed_algorithms: Vec<Algorithm>) -> CosePolicy {
    CosePolicy::new()
        .with_require_kid(true)
        .with_allowed_algorithms(allowed_algorithms)
}

fn execute_create(operation: Operation) -> Zeroizing<Vec<u8>> {
    let payload = execute(operation);
    let mut result = CoseSign1CreateResult::decode_from_slice(&payload)
        .expect("Sign1 create result must decode");
    Zeroizing::new(core::mem::take(&mut result.cose_sign1))
}

fn execute_verify(operation: Operation) -> CoseSign1VerifyResult {
    CoseSign1VerifyResult::decode_from_slice(&execute(operation))
        .expect("Sign1 verify result must decode")
}

fn execute(operation: Operation) -> Zeroizing<Vec<u8>> {
    let request = operation_request(operation);
    let binary_request = Zeroizing::new(request.encode_to_vec());
    let json_request = Zeroizing::new(
        serde_json::to_string(&request).expect("generated Sign1 ProtoJSON must encode"),
    );
    let binary_envelope = execute_operation_proto(&binary_request);
    let json_envelope = execute_operation_proto_json(&json_request);
    assert_eq!(binary_envelope.as_slice(), json_envelope.as_slice());
    let output = decode_operation_output(&binary_envelope)
        .ok()
        .expect("successful Sign1 envelope must decode");
    assert_eq!(output.status(), OperationOutputStatus::Result);
    Zeroizing::new(output.bytes().to_vec())
}

fn assert_error(operation: Operation, expected_branch: ErrorBranch, expected: CoseErrorReason) {
    let request = operation_request(operation);
    let binary_request = Zeroizing::new(request.encode_to_vec());
    let json_request = Zeroizing::new(
        serde_json::to_string(&request).expect("generated Sign1 ProtoJSON must encode"),
    );
    let binary_envelope = execute_operation_proto(&binary_request);
    let json_envelope = execute_operation_proto_json(&json_request);
    assert_eq!(binary_envelope.as_slice(), json_envelope.as_slice());
    let output = match decode_operation_output(&binary_envelope) {
        Ok(output) | Err(output) => output,
    };
    assert_eq!(output.status(), OperationOutputStatus::CoseError);
    let error = decode_cose_error(output.bytes()).expect("structured Sign1 error must decode");
    let Some(branch) = error.error.as_ref() else {
        assert!(error.error.is_some(), "structured error branch must exist");
        return;
    };
    let (branch, reason) = match branch {
        cose_error_proto::Error::Primitive(error) => {
            (ErrorBranch::Primitive, error.reason.as_known())
        }
        cose_error_proto::Error::Provider(error) => {
            (ErrorBranch::Provider, error.reason.as_known())
        }
        cose_error_proto::Error::Backend(error) => (ErrorBranch::Backend, error.reason.as_known()),
    };
    assert_eq!(branch, expected_branch);
    assert_eq!(reason, Some(expected));
}

fn assert_native_error<T>(result: Result<T, CoseError>, expected: CoseError) {
    assert!(matches!(result, Err(error) if error == expected));
}

fn operation_request(operation: Operation) -> CoseOperationRequest {
    CoseOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    }
}
