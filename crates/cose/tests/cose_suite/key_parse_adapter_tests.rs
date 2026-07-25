// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use buffa::Message;
use reallyme_cose::limits::MAX_COSE_KEY_BYTES;
use reallyme_cose::wire::cose_operation_request::Operation;
use reallyme_cose::wire::{
    cose_error_proto, decode_cose_error, execute_operation_proto, execute_operation_proto_json,
    CoseErrorProto, CoseErrorReason, CoseKeyBytesRequest, CoseKeyBytesResult, CoseOperationRequest,
};
use reallyme_cose::{cose_key_from_public_bytes, cose_key_to_vec, Algorithm};

use crate::support::{decode_operation_output, OperationOutput, OperationOutputStatus};

const RFC_8032_ED25519_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

#[derive(Clone, Copy)]
enum AdapterLane {
    Protobuf,
    ProtoJson,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorBranch {
    Primitive,
    Provider,
    Backend,
}

#[test]
fn key_parse_adapters_return_canonical_key_bytes() {
    let key = cose_key_from_public_bytes(Algorithm::Ed25519, &RFC_8032_ED25519_PUBLIC_KEY)
        .expect("fixture key must be valid");
    let encoded = cose_key_to_vec(&key).expect("fixture key must encode");

    for lane in [AdapterLane::Protobuf, AdapterLane::ProtoJson] {
        let output = execute(lane, encoded.to_vec());
        assert_eq!(output.status(), OperationOutputStatus::Result);
        let result = CoseKeyBytesResult::decode_from_slice(output.bytes())
            .expect("key parse result must decode");
        assert_eq!(result.key_bytes, encoded.as_slice());
    }
}

#[test]
fn key_parse_adapters_preserve_semantic_failures() {
    let oversized_len = MAX_COSE_KEY_BYTES
        .checked_add(1)
        .expect("test length must fit usize");
    let cases = [
        (Vec::new(), CoseErrorReason::CommonCbor),
        (
            vec![0_u8; oversized_len],
            CoseErrorReason::CommonResourceLimitExceeded,
        ),
        (
            vec![0xa2, 0x01, 0x01, 0x01, 0x01],
            CoseErrorReason::CommonDuplicateMapLabel,
        ),
    ];

    for lane in [AdapterLane::Protobuf, AdapterLane::ProtoJson] {
        for (input, expected_reason) in &cases {
            assert_error(
                &execute(lane, input.clone()),
                ErrorBranch::Primitive,
                *expected_reason,
            );
        }
    }
}

#[test]
fn malformed_transport_stays_separate_from_semantic_failure() {
    let protobuf = decode_envelope(&execute_operation_proto(&[0xff]));
    assert_error(
        &protobuf,
        ErrorBranch::Primitive,
        CoseErrorReason::CommonMalformedProtobuf,
    );

    let proto_json = decode_envelope(&execute_operation_proto_json("{"));
    assert_error(
        &proto_json,
        ErrorBranch::Primitive,
        CoseErrorReason::CommonMalformedJson,
    );
}

fn execute(lane: AdapterLane, cose_key: Vec<u8>) -> OperationOutput {
    let request = CoseOperationRequest {
        operation: Some(Operation::KeyParse(Box::new(CoseKeyBytesRequest {
            cose_key,
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };

    match lane {
        AdapterLane::Protobuf => {
            decode_envelope(&execute_operation_proto(&request.encode_to_vec()))
        }
        AdapterLane::ProtoJson => {
            let json = serde_json::to_string(&request).expect("request ProtoJSON must encode");
            decode_envelope(&execute_operation_proto_json(&json))
        }
    }
}

fn decode_envelope(bytes: &[u8]) -> OperationOutput {
    match decode_operation_output(bytes) {
        Ok(output) | Err(output) => output,
    }
}

fn assert_error(output: &OperationOutput, branch: ErrorBranch, reason: CoseErrorReason) {
    assert_eq!(output.status(), OperationOutputStatus::CoseError);
    let error = decode_cose_error(output.bytes()).ok();
    assert!(error.is_some(), "structured error must decode");
    let Some(error) = error else {
        return;
    };
    assert_eq!(error_branch(&error), Some(branch));
    assert_eq!(error_reason(&error), Some(reason));
}

fn error_branch(error: &CoseErrorProto) -> Option<ErrorBranch> {
    match error.error.as_ref()? {
        cose_error_proto::Error::Primitive(_) => Some(ErrorBranch::Primitive),
        cose_error_proto::Error::Provider(_) => Some(ErrorBranch::Provider),
        cose_error_proto::Error::Backend(_) => Some(ErrorBranch::Backend),
    }
}

fn error_reason(error: &CoseErrorProto) -> Option<CoseErrorReason> {
    let reason = match error.error.as_ref()? {
        cose_error_proto::Error::Primitive(value) => value.reason,
        cose_error_proto::Error::Provider(value) => value.reason,
        cose_error_proto::Error::Backend(value) => value.reason,
    };
    reason.as_known()
}
