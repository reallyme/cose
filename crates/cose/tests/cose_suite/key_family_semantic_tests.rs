// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use buffa::{EnumValue, Message};
use reallyme_cose::wire::cose_operation_request::Operation;
use reallyme_cose::wire::{
    cose_algorithm_identifier, cose_error_proto, decode_cose_error, execute_operation_proto,
    execute_operation_proto_json, CoseAlgorithmIdentifier, CoseErrorReason, CoseKemAlgorithm,
    CoseKeyBytesRequest, CoseKeyBytesResult, CoseKeyFromPrivateBytesRequest,
    CoseKeyFromPublicBytesRequest, CoseMultikeyResult, CoseMultikeyToCoseKeyRequest,
    CoseOperationRequest, CoseSignatureAlgorithm,
};
use reallyme_cose::{
    cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_to_multikey, cose_key_to_vec,
    derive_kid_from_cose_key_public, multikey_to_cose_key,
};
use zeroize::Zeroizing;

use super::support::{decode_operation_output, gen_ed25519, OperationOutputStatus};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorBranch {
    Primitive,
    Provider,
    Backend,
}

#[test]
fn remaining_key_family_operations_match_native_binary_and_proto_json() {
    let mut fixture = gen_ed25519();
    let public_key = Zeroizing::new(core::mem::take(&mut fixture.public));
    let private_key = Zeroizing::new(core::mem::take(&mut fixture.private));

    let native_public = cose_key_from_public_bytes(fixture.alg, &public_key)
        .expect("public fixture must construct");
    let encoded_public = cose_key_to_vec(&native_public).expect("public fixture must encode");
    let constructed_public = execute_key_bytes(Operation::KeyFromPublicBytes(Box::new(
        CoseKeyFromPublicBytesRequest {
            algorithm: ed25519_identifier(),
            public_key: public_key.to_vec(),
            __buffa_unknown_fields: Default::default(),
        },
    )));
    assert_eq!(constructed_public.as_slice(), encoded_public.as_slice());

    let native_private = cose_key_from_private_bytes(fixture.alg, &private_key, Some(&public_key))
        .expect("private fixture must construct");
    let encoded_private =
        cose_key_to_vec(&native_private).expect("constructed private key must encode canonically");
    let constructed_private = execute_key_bytes(Operation::KeyFromPrivateBytes(Box::new(
        CoseKeyFromPrivateBytesRequest {
            algorithm: ed25519_identifier(),
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
            has_public_key: true,
            __buffa_unknown_fields: Default::default(),
        },
    )));
    assert_eq!(constructed_private.as_slice(), encoded_private.as_slice());

    let extracted_public = execute_key_bytes(Operation::KeyToPublicBytes(Box::new(key_request(
        &encoded_private,
    ))));
    assert_eq!(extracted_public.as_slice(), public_key.as_slice());

    let extracted_private = execute_key_bytes(Operation::KeyToPrivateBytes(Box::new(key_request(
        &encoded_private,
    ))));
    assert_eq!(extracted_private.as_slice(), private_key.as_slice());

    let native_kid = Zeroizing::new(
        derive_kid_from_cose_key_public(&native_private).expect("kid derivation must succeed"),
    );
    let derived_kid = execute_key_bytes(Operation::KeyDerivePublicKid(Box::new(key_request(
        &encoded_private,
    ))));
    assert_eq!(derived_kid.as_slice(), native_kid.as_slice());

    let native_multikey = Zeroizing::new(
        cose_key_to_multikey(&native_private).expect("Multikey conversion must succeed"),
    );
    let converted_multikey = execute_multikey(Operation::KeyToMultikey(Box::new(key_request(
        &encoded_private,
    ))));
    assert_eq!(converted_multikey.as_str(), native_multikey.as_str());

    let native_from_multikey =
        multikey_to_cose_key(&native_multikey).expect("Multikey fixture must parse");
    let native_from_multikey =
        cose_key_to_vec(&native_from_multikey).expect("Multikey key must encode");
    let converted_key = execute_key_bytes(Operation::MultikeyToCoseKey(Box::new(
        CoseMultikeyToCoseKeyRequest {
            multikey: native_multikey.to_string(),
            __buffa_unknown_fields: Default::default(),
        },
    )));
    assert_eq!(converted_key.as_slice(), native_from_multikey.as_slice());
}

#[test]
fn remaining_key_family_failures_preserve_exact_branch_and_reason() {
    let mut fixture = gen_ed25519();
    let public_key = Zeroizing::new(core::mem::take(&mut fixture.public));
    let private_key = Zeroizing::new(core::mem::take(&mut fixture.private));
    let public_cose_key = cose_key_from_public_bytes(fixture.alg, &public_key)
        .and_then(|key| cose_key_to_vec(&key))
        .expect("public fixture must encode");

    assert_error(
        Operation::KeyFromPublicBytes(Box::new(CoseKeyFromPublicBytesRequest {
            algorithm: ed25519_identifier(),
            public_key: vec![0_u8; 31],
            __buffa_unknown_fields: Default::default(),
        })),
        ErrorBranch::Primitive,
        CoseErrorReason::KeyInvalidKeyMaterial,
    );
    assert_error(
        Operation::KeyFromPrivateBytes(Box::new(CoseKeyFromPrivateBytesRequest {
            algorithm: ed25519_identifier(),
            private_key: private_key.to_vec(),
            public_key: Vec::new(),
            has_public_key: false,
            __buffa_unknown_fields: Default::default(),
        })),
        ErrorBranch::Primitive,
        CoseErrorReason::KeyMissingKeyMaterial,
    );
    assert_error(
        Operation::KeyToPrivateBytes(Box::new(key_request(&public_cose_key))),
        ErrorBranch::Primitive,
        CoseErrorReason::KeyMissingKeyMaterial,
    );
    assert_error(
        Operation::MultikeyToCoseKey(Box::new(CoseMultikeyToCoseKeyRequest {
            multikey: "not-a-multikey".to_owned(),
            __buffa_unknown_fields: Default::default(),
        })),
        ErrorBranch::Primitive,
        CoseErrorReason::MultikeyInvalidMultikey,
    );
    assert_error(
        Operation::KeyFromPublicBytes(Box::new(CoseKeyFromPublicBytesRequest {
            algorithm: buffa::MessageField::some(CoseAlgorithmIdentifier {
                algorithm: Some(cose_algorithm_identifier::Algorithm::Kem(EnumValue::from(
                    CoseKemAlgorithm::XWing768,
                ))),
                __buffa_unknown_fields: Default::default(),
            }),
            public_key: public_key.to_vec(),
            __buffa_unknown_fields: Default::default(),
        })),
        ErrorBranch::Provider,
        CoseErrorReason::CommonUnsupportedAlgorithm,
    );
}

fn ed25519_identifier(
) -> buffa::MessageField<CoseAlgorithmIdentifier, buffa::Inline<CoseAlgorithmIdentifier>> {
    buffa::MessageField::some(CoseAlgorithmIdentifier {
        algorithm: Some(cose_algorithm_identifier::Algorithm::Signature(
            EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        )),
        __buffa_unknown_fields: Default::default(),
    })
}

fn key_request(encoded: &[u8]) -> CoseKeyBytesRequest {
    CoseKeyBytesRequest {
        cose_key: encoded.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn operation_request(operation: Operation) -> CoseOperationRequest {
    CoseOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    }
}

fn execute_key_bytes(operation: Operation) -> Zeroizing<Vec<u8>> {
    let payload = execute(operation);
    let mut result = CoseKeyBytesResult::decode_from_slice(&payload)
        .expect("key-family result must decode as CoseKeyBytesResult");
    Zeroizing::new(core::mem::take(&mut result.key_bytes))
}

fn execute_multikey(operation: Operation) -> Zeroizing<String> {
    let payload = execute(operation);
    let mut result = CoseMultikeyResult::decode_from_slice(&payload)
        .expect("key-family result must decode as CoseMultikeyResult");
    Zeroizing::new(core::mem::take(&mut result.multikey))
}

fn execute(operation: Operation) -> Zeroizing<Vec<u8>> {
    let request = operation_request(operation);
    let encoded_request = Zeroizing::new(request.encode_to_vec());
    let json_request = Zeroizing::new(
        serde_json::to_string(&request).expect("generated request ProtoJSON must encode"),
    );
    let binary_envelope = execute_operation_proto(&encoded_request);
    let json_envelope = execute_operation_proto_json(&json_request);
    assert_eq!(binary_envelope.as_slice(), json_envelope.as_slice());

    let output = decode_operation_output(&binary_envelope)
        .ok()
        .expect("successful key-family envelope must decode");
    assert_eq!(output.status(), OperationOutputStatus::Result);
    Zeroizing::new(output.bytes().to_vec())
}

fn assert_error(
    operation: Operation,
    expected_branch: ErrorBranch,
    expected_reason: CoseErrorReason,
) {
    let request = operation_request(operation);
    let encoded_request = Zeroizing::new(request.encode_to_vec());
    let json_request = Zeroizing::new(
        serde_json::to_string(&request).expect("generated request ProtoJSON must encode"),
    );
    let binary_envelope = execute_operation_proto(&encoded_request);
    let json_envelope = execute_operation_proto_json(&json_request);
    assert_eq!(binary_envelope.as_slice(), json_envelope.as_slice());

    let output = match decode_operation_output(&binary_envelope) {
        Ok(output) | Err(output) => output,
    };
    assert_eq!(output.status(), OperationOutputStatus::CoseError);
    let error = decode_cose_error(output.bytes()).expect("structured key-family error must decode");
    let Some(error_branch) = error.error.as_ref() else {
        assert!(error.error.is_some(), "structured error branch must exist");
        return;
    };
    let (branch, reason) = match error_branch {
        cose_error_proto::Error::Primitive(error) => {
            (ErrorBranch::Primitive, error.reason.as_known())
        }
        cose_error_proto::Error::Provider(error) => {
            (ErrorBranch::Provider, error.reason.as_known())
        }
        cose_error_proto::Error::Backend(error) => (ErrorBranch::Backend, error.reason.as_known()),
    };
    assert_eq!(branch, expected_branch);
    assert_eq!(reason, Some(expected_reason));
}
