// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Cursor;

use buffa::{EnumValue, Message};
use ciborium::{ser::into_writer, value::Value};
use reallyme_cose::limits::MAX_COSE_KEY_BYTES;
use reallyme_cose::wire::cose_error_proto;
use reallyme_cose::wire::cose_operation_request::Operation;
use reallyme_cose::wire::{
    cose_operation_response_v2, cose_operation_result, decode_cose_error, execute_operation_proto,
    execute_operation_proto_json, CoseBackendError, CoseErrorProto, CoseErrorReason,
    CoseKeyBytesRequest, CoseKeyBytesResult, CoseOperationRequest, CoseOperationResponseV2,
    CoseOperationResult, CosePrimitiveError, CoseProviderError, MAX_COSE_PROTO_MESSAGE_BYTES,
};
use reallyme_cose::{
    cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_from_slice, cose_key_to_vec,
    Algorithm, CoseError,
};
use reallyme_crypto::dispatch::generate_keypair;
use zeroize::Zeroizing;

use crate::support::{decode_operation_output, OperationOutput, OperationOutputStatus};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedBranch {
    Primitive,
    Provider,
    Backend,
}

#[derive(Clone, Copy)]
enum ExpectedNative {
    Cbor,
    InvalidKeyMaterial,
    MissingKeyMaterial,
    NonCanonicalCbor,
    ResourceLimitExceeded,
    UnexpectedCborTag,
    DuplicateMapLabel,
    UnsupportedAlgorithm,
}

#[derive(Clone, Copy)]
struct ExpectedFailure {
    native: ExpectedNative,
    branch: ExpectedBranch,
    reason: CoseErrorReason,
}

#[test]
fn native_protobuf_and_proto_json_success_outputs_are_identical() {
    for (fixture_index, encoded) in success_fixtures().into_iter().enumerate() {
        let native = cose_key_from_slice(&encoded);
        assert!(
            native.is_ok(),
            "native success fixture {fixture_index} failed with {:?}",
            native.as_ref().err(),
        );
        let Ok(native) = native else {
            return;
        };
        let native_bytes = cose_key_to_vec(&native).expect("native result must encode");
        let expected_envelope = expected_result_envelope(&native_bytes);
        let (protobuf_envelope, json_envelope) = execute_adapters(&encoded);

        assert_eq!(protobuf_envelope.as_slice(), expected_envelope.as_slice());
        assert_eq!(json_envelope.as_slice(), expected_envelope.as_slice());
        assert_eq!(protobuf_envelope.as_slice(), json_envelope.as_slice());

        let protobuf_result = decode_key_result(&protobuf_envelope);
        let json_result = decode_key_result(&json_envelope);
        assert_eq!(protobuf_result.key_bytes, native_bytes.as_slice());
        assert_eq!(json_result.key_bytes, native_bytes.as_slice());
    }
}

#[test]
fn hostile_semantic_inputs_preserve_exact_native_and_wire_failures() {
    for (fixture_index, (input, expected)) in failure_fixtures().into_iter().enumerate() {
        assert_native_error(
            cose_key_from_slice(&input).err(),
            expected.native,
            fixture_index,
        );

        let expected_envelope = expected_error_envelope(expected);
        let (protobuf_envelope, json_envelope) = execute_adapters(&input);
        assert_eq!(protobuf_envelope.as_slice(), expected_envelope.as_slice());
        assert_eq!(json_envelope.as_slice(), expected_envelope.as_slice());

        assert_error(&protobuf_envelope, expected);
        assert_error(&json_envelope, expected);
    }
}

#[test]
fn adapter_only_failures_do_not_enter_key_semantics() {
    let missing_operation = CoseOperationRequest {
        operation: None,
        __buffa_unknown_fields: Default::default(),
    };
    assert_error(
        &execute_operation_proto(&missing_operation.encode_to_vec()),
        primitive(
            ExpectedNative::Cbor,
            CoseErrorReason::CommonInvalidParameter,
        ),
    );

    let oversized_len = MAX_COSE_PROTO_MESSAGE_BYTES
        .checked_add(1)
        .expect("protobuf test length must fit usize");
    let oversized = vec![0_u8; oversized_len];
    assert_error(
        &execute_operation_proto(&oversized),
        primitive(
            ExpectedNative::ResourceLimitExceeded,
            CoseErrorReason::CommonResourceLimitExceeded,
        ),
    );
}

#[test]
fn concurrent_parses_are_deterministic_and_independently_owned() {
    let encoded = success_fixtures()
        .into_iter()
        .next()
        .expect("at least one fixture must exist");
    let expected = encoded.to_vec();

    let mut outputs = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let input = encoded.as_slice();
                scope.spawn(move || {
                    let key = cose_key_from_slice(input).expect("concurrent parse must succeed");
                    cose_key_to_vec(&key).expect("concurrent result must encode")
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("concurrent parse must not panic"))
            .collect::<Vec<_>>()
    });

    assert!(outputs
        .iter()
        .all(|output| output.as_slice() == expected.as_slice()));
    outputs[0][0] ^= 0x01;
    assert!(outputs[1..]
        .iter()
        .all(|output| output.as_slice() == expected.as_slice()));
}

fn success_fixtures() -> Vec<Zeroizing<Vec<u8>>> {
    let (classical_public, classical_private) =
        generate_keypair(Algorithm::Ed25519).expect("Ed25519 fixture generation must succeed");
    let (pq_public, pq_private) =
        generate_keypair(Algorithm::MlKem768).expect("ML-KEM-768 fixture generation must succeed");

    vec![
        encode_public(Algorithm::Ed25519, &classical_public),
        encode_ed25519_private(&classical_private, &classical_public),
        encode_public(Algorithm::MlKem768, &pq_public),
        encode_private(Algorithm::MlKem768, &pq_private, &pq_public),
    ]
}

fn failure_fixtures() -> Vec<(Zeroizing<Vec<u8>>, ExpectedFailure)> {
    let mut cases = vec![
        (
            Zeroizing::new(vec![0xff]),
            primitive(ExpectedNative::Cbor, CoseErrorReason::CommonCbor),
        ),
        (
            Zeroizing::new(vec![0xbf, 0xff]),
            primitive(
                ExpectedNative::NonCanonicalCbor,
                CoseErrorReason::CommonNonCanonicalCbor,
            ),
        ),
        (
            Zeroizing::new(vec![0xa1, 0x18, 0x01, 0x01]),
            primitive(
                ExpectedNative::NonCanonicalCbor,
                CoseErrorReason::CommonNonCanonicalCbor,
            ),
        ),
        (
            Zeroizing::new(vec![0xa2, 0x01, 0x01, 0x01, 0x01]),
            primitive(
                ExpectedNative::DuplicateMapLabel,
                CoseErrorReason::CommonDuplicateMapLabel,
            ),
        ),
        (
            Zeroizing::new(vec![0xc1, 0xa0]),
            primitive(
                ExpectedNative::UnexpectedCborTag,
                CoseErrorReason::CommonUnexpectedCborTag,
            ),
        ),
        (
            Zeroizing::new(vec![0xa0, 0x00]),
            primitive(ExpectedNative::Cbor, CoseErrorReason::CommonCbor),
        ),
        (
            deeply_nested_input(),
            primitive(
                ExpectedNative::ResourceLimitExceeded,
                CoseErrorReason::CommonResourceLimitExceeded,
            ),
        ),
        (
            Zeroizing::new(vec![0xb9, 0x04, 0x01]),
            primitive(
                ExpectedNative::ResourceLimitExceeded,
                CoseErrorReason::CommonResourceLimitExceeded,
            ),
        ),
        (
            Zeroizing::new(vec![
                0_u8;
                MAX_COSE_KEY_BYTES
                    .checked_add(1)
                    .expect("COSE_Key test length must fit usize")
            ]),
            primitive(
                ExpectedNative::ResourceLimitExceeded,
                CoseErrorReason::CommonResourceLimitExceeded,
            ),
        ),
        (
            missing_key_material_input(),
            primitive(
                ExpectedNative::MissingKeyMaterial,
                CoseErrorReason::KeyMissingKeyMaterial,
            ),
        ),
        (
            invalid_key_length_input(),
            primitive(
                ExpectedNative::InvalidKeyMaterial,
                CoseErrorReason::KeyInvalidKeyMaterial,
            ),
        ),
        (
            unsupported_algorithm_input(),
            ExpectedFailure {
                native: ExpectedNative::UnsupportedAlgorithm,
                branch: ExpectedBranch::Provider,
                reason: CoseErrorReason::CommonUnsupportedAlgorithm,
            },
        ),
    ];
    cases.push((
        mismatched_private_key_input(),
        primitive(
            ExpectedNative::InvalidKeyMaterial,
            CoseErrorReason::KeyInvalidKeyMaterial,
        ),
    ));
    cases
}

fn primitive(native: ExpectedNative, reason: CoseErrorReason) -> ExpectedFailure {
    ExpectedFailure {
        native,
        branch: ExpectedBranch::Primitive,
        reason,
    }
}

fn encode_public(algorithm: Algorithm, public_key: &[u8]) -> Zeroizing<Vec<u8>> {
    let key = cose_key_from_public_bytes(algorithm, public_key)
        .expect("public fixture COSE_Key must build");
    cose_key_to_vec(&key).expect("public fixture COSE_Key must encode")
}

fn encode_private(
    algorithm: Algorithm,
    private_key: &[u8],
    public_key: &[u8],
) -> Zeroizing<Vec<u8>> {
    let key = cose_key_from_private_bytes(algorithm, private_key, Some(public_key))
        .expect("private fixture COSE_Key must build");
    cose_key_to_vec(&key).expect("private fixture COSE_Key must encode")
}

fn encode_ed25519_private(private_key: &[u8], public_key: &[u8]) -> Zeroizing<Vec<u8>> {
    // Assemble kty, alg, crv, x, and d in RFC 8949 bytewise map-key order so
    // this parse fixture is independent of the separate construction route.
    let mut encoded = Zeroizing::new(vec![
        0xa5, 0x01, 0x01, 0x03, 0x32, 0x20, 0x06, 0x21, 0x58, 0x20,
    ]);
    encoded.extend_from_slice(public_key);
    encoded.extend_from_slice(&[0x23, 0x58, 0x20]);
    encoded.extend_from_slice(private_key);
    encoded
}

fn deeply_nested_input() -> Zeroizing<Vec<u8>> {
    let mut value = Value::Null;
    for _ in 0..40 {
        value = Value::Array(vec![value]);
    }
    let mut encoded = Zeroizing::new(Vec::new());
    into_writer(&value, Cursor::new(&mut *encoded)).expect("nested fixture must encode");
    encoded
}

fn missing_key_material_input() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(vec![0xa3, 0x01, 0x01, 0x03, 0x32, 0x20, 0x06])
}

fn invalid_key_length_input() -> Zeroizing<Vec<u8>> {
    let mut encoded = Zeroizing::new(vec![
        0xa4, 0x01, 0x01, 0x03, 0x32, 0x20, 0x06, 0x21, 0x58, 0x1f,
    ]);
    encoded.extend_from_slice(&[0_u8; 31]);
    encoded
}

fn unsupported_algorithm_input() -> Zeroizing<Vec<u8>> {
    let mut encoded = Zeroizing::new(vec![
        0xa4, 0x01, 0x01, 0x03, 0x26, 0x20, 0x06, 0x21, 0x58, 0x20,
    ]);
    encoded.extend_from_slice(&[0_u8; 32]);
    encoded
}

fn mismatched_private_key_input() -> Zeroizing<Vec<u8>> {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("first Ed25519 fixture must generate");
    let (_, other_private_key) =
        generate_keypair(Algorithm::Ed25519).expect("second Ed25519 fixture must generate");
    let mut encoded = encode_ed25519_private(&private_key, &public_key);
    let offset = encoded
        .windows(private_key.len())
        .position(|window| window == private_key.as_slice())
        .expect("private key bytes must occur in encoded fixture");
    let end = offset
        .checked_add(other_private_key.len())
        .expect("fixture private-key offset must not overflow");
    encoded[offset..end].copy_from_slice(&other_private_key);
    encoded
}

fn execute_adapters(input: &[u8]) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let request = operation_request(input);
    let protobuf = execute_operation_proto(&request.encode_to_vec());
    let json = Zeroizing::new(
        serde_json::to_string(&request).expect("generated request ProtoJSON must encode"),
    );
    let proto_json = execute_operation_proto_json(&json);
    (protobuf, proto_json)
}

fn operation_request(input: &[u8]) -> CoseOperationRequest {
    CoseOperationRequest {
        operation: Some(Operation::KeyParse(Box::new(CoseKeyBytesRequest {
            cose_key: input.to_vec(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn expected_result_envelope(key_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let result = CoseKeyBytesResult {
        key_bytes: key_bytes.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    Zeroizing::new(
        CoseOperationResponseV2 {
            outcome: Some(cose_operation_response_v2::Outcome::Result(Box::new(
                CoseOperationResult {
                    result: Some(cose_operation_result::Result::KeyParse(Box::new(result))),
                    __buffa_unknown_fields: Default::default(),
                },
            ))),
            __buffa_unknown_fields: Default::default(),
        }
        .encode_to_vec(),
    )
}

fn expected_error_envelope(expected: ExpectedFailure) -> Zeroizing<Vec<u8>> {
    let reason = EnumValue::from(expected.reason);
    let error = CoseErrorProto {
        error: Some(match expected.branch {
            ExpectedBranch::Primitive => {
                cose_error_proto::Error::Primitive(Box::new(CosePrimitiveError {
                    reason,
                    __buffa_unknown_fields: Default::default(),
                }))
            }
            ExpectedBranch::Provider => {
                cose_error_proto::Error::Provider(Box::new(CoseProviderError {
                    reason,
                    __buffa_unknown_fields: Default::default(),
                }))
            }
            ExpectedBranch::Backend => {
                cose_error_proto::Error::Backend(Box::new(CoseBackendError {
                    reason,
                    __buffa_unknown_fields: Default::default(),
                }))
            }
        }),
        __buffa_unknown_fields: Default::default(),
    };
    Zeroizing::new(
        CoseOperationResponseV2 {
            outcome: Some(cose_operation_response_v2::Outcome::Error(Box::new(error))),
            __buffa_unknown_fields: Default::default(),
        }
        .encode_to_vec(),
    )
}

fn decode_key_result(envelope: &[u8]) -> CoseKeyBytesResult {
    let output = decode_output(envelope);
    assert_eq!(output.status(), OperationOutputStatus::Result);
    CoseKeyBytesResult::decode_from_slice(output.bytes()).expect("key result must decode")
}

fn assert_error(envelope: &[u8], expected: ExpectedFailure) {
    let output = decode_output(envelope);
    assert_eq!(output.status(), OperationOutputStatus::CoseError);
    let error = decode_cose_error(output.bytes()).ok();
    assert!(error.is_some(), "structured error must decode");
    let Some(error) = error else {
        return;
    };
    let error_branch = error.error.as_ref();
    assert!(error_branch.is_some(), "error branch must exist");
    let Some(error_branch) = error_branch else {
        return;
    };
    let (branch, reason) = match error_branch {
        cose_error_proto::Error::Primitive(value) => (ExpectedBranch::Primitive, value.reason),
        cose_error_proto::Error::Provider(value) => (ExpectedBranch::Provider, value.reason),
        cose_error_proto::Error::Backend(value) => (ExpectedBranch::Backend, value.reason),
    };
    assert_eq!(branch, expected.branch);
    assert_eq!(reason.as_known(), Some(expected.reason));
}

fn assert_native_error(actual: Option<CoseError>, expected: ExpectedNative, fixture_index: usize) {
    let matches = matches!(
        (actual, expected),
        (Some(CoseError::Cbor), ExpectedNative::Cbor)
            | (
                Some(CoseError::InvalidKeyMaterial),
                ExpectedNative::InvalidKeyMaterial
            )
            | (
                Some(CoseError::MissingKeyMaterial),
                ExpectedNative::MissingKeyMaterial
            )
            | (
                Some(CoseError::NonCanonicalCbor),
                ExpectedNative::NonCanonicalCbor
            )
            | (
                Some(CoseError::ResourceLimitExceeded),
                ExpectedNative::ResourceLimitExceeded
            )
            | (
                Some(CoseError::UnexpectedCborTag),
                ExpectedNative::UnexpectedCborTag
            )
            | (
                Some(CoseError::DuplicateMapLabel),
                ExpectedNative::DuplicateMapLabel
            )
            | (
                Some(CoseError::UnsupportedAlgorithm),
                ExpectedNative::UnsupportedAlgorithm
            )
    );
    assert!(
        matches,
        "native failure fixture {fixture_index} did not match the expected typed variant"
    );
}

fn decode_output(envelope: &[u8]) -> OperationOutput {
    match decode_operation_output(envelope) {
        Ok(output) | Err(output) => output,
    }
}
