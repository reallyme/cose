// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated-wire coverage for explicit EC2 point representations.

#![allow(clippy::panic)]

use buffa::{EnumValue, Message};
use ciborium::value::Value;
use coset::{iana, CborSerializable, CoseKey as RawCoseKey, Label};
use reallyme_cose::wire::{
    cose_algorithm_identifier, cose_error_proto, cose_operation_request, decode_cose_error,
    execute_operation_proto, execute_operation_proto_json, CoseAlgorithmIdentifier,
    CoseEc2PointEncoding, CoseErrorReason, CoseKeyBytesResult, CoseKeyFromPublicBytesRequest,
    CoseOperationRequest, CoseSignatureAlgorithm,
};

use super::support::{decode_operation_output, gen_ed25519, gen_p256, OperationOutputStatus};

fn signature_identifier(
    algorithm: CoseSignatureAlgorithm,
) -> buffa::MessageField<CoseAlgorithmIdentifier, buffa::Inline<CoseAlgorithmIdentifier>> {
    buffa::MessageField::some(CoseAlgorithmIdentifier {
        algorithm: Some(cose_algorithm_identifier::Algorithm::Signature(
            EnumValue::from(algorithm),
        )),
        __buffa_unknown_fields: Default::default(),
    })
}

fn operation_request(request: CoseKeyFromPublicBytesRequest) -> CoseOperationRequest {
    CoseOperationRequest {
        operation: Some(cose_operation_request::Operation::KeyFromPublicBytes(
            Box::new(request),
        )),
        __buffa_unknown_fields: Default::default(),
    }
}

fn execute(request: &CoseOperationRequest) -> super::support::OperationOutput {
    let envelope = execute_operation_proto(&request.encode_to_vec());
    match decode_operation_output(&envelope) {
        Ok(output) | Err(output) => output,
    }
}

fn assert_invalid_parameter(request: &CoseOperationRequest) {
    let output = execute(request);
    assert_eq!(output.status(), OperationOutputStatus::CoseError);
    let error = decode_cose_error(output.bytes()).expect("structured COSE error");
    let Some(cose_error_proto::Error::Primitive(primitive)) = error.error else {
        panic!("point-encoding policy must fail as a primitive error");
    };
    assert_eq!(
        primitive.reason.as_known(),
        Some(CoseErrorReason::CommonInvalidParameter),
    );
}

#[test]
fn es256_wire_contract_selects_full_affine_coordinates() {
    let key = gen_p256();
    let request = operation_request(CoseKeyFromPublicBytesRequest {
        algorithm: signature_identifier(CoseSignatureAlgorithm::Es256),
        public_key: key.public,
        ec2_point_encoding: EnumValue::from(CoseEc2PointEncoding::FullCoordinates),
        __buffa_unknown_fields: Default::default(),
    });

    let binary_output = execute(&request);
    let json = serde_json::to_string(&request).expect("full-affine request JSON");
    let json_envelope = execute_operation_proto_json(&json);
    let json_output = match decode_operation_output(&json_envelope) {
        Ok(output) | Err(output) => output,
    };
    assert_eq!(binary_output.status(), OperationOutputStatus::Result);
    assert_eq!(json_output.status(), OperationOutputStatus::Result);
    assert_eq!(binary_output.bytes(), json_output.bytes());

    let result = CoseKeyBytesResult::decode_from_slice(binary_output.bytes())
        .expect("full-affine key result");
    let key = RawCoseKey::from_slice(&result.key_bytes).expect("full-affine COSE_Key");
    let y_label = Label::Int(iana::Ec2KeyParameter::Y as i64);
    let y = key
        .params
        .iter()
        .find_map(|(label, value)| (label == &y_label).then_some(value))
        .expect("EC2 Y parameter");
    assert!(matches!(y, Value::Bytes(bytes) if bytes.len() == 32));
}

#[test]
fn ec2_point_encoding_rejects_unknown_and_non_ec2_values() {
    let key = gen_p256();
    assert_invalid_parameter(&operation_request(CoseKeyFromPublicBytesRequest {
        algorithm: signature_identifier(CoseSignatureAlgorithm::Es256),
        public_key: key.public,
        ec2_point_encoding: EnumValue::from(999_999),
        __buffa_unknown_fields: Default::default(),
    }));

    let ed25519 = gen_ed25519();
    assert_invalid_parameter(&operation_request(CoseKeyFromPublicBytesRequest {
        algorithm: signature_identifier(CoseSignatureAlgorithm::Ed25519),
        public_key: ed25519.public,
        ec2_point_encoding: EnumValue::from(CoseEc2PointEncoding::FullCoordinates),
        __buffa_unknown_fields: Default::default(),
    }));
}
