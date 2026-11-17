// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{field, hex};
use crate::api::contract as wire;
use crate::{CoseError, CoseSignatureAlgorithm};
use ciborium::value::Value;
use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct Vectors {
    pub schema: String,
    pub public_spki: String,
    pub public_pkcs1: String,
    pub wrong_public_spki: String,
    pub weak_public_spki: String,
    pub below_minimum_public_spki: String,
    pub payload: String,
    pub aad: String,
    pub body_protected: String,
    pub counter_target: String,
    pub max_payload_bytes: usize,
    pub max_signature: String,
    pub cases: Vec<Case>,
}
#[derive(Deserialize)]
pub(super) struct Case {
    pub id: String,
    pub registration: i64,
    pub protected: String,
    pub signature: String,
    pub sign1_structure: String,
    pub sign1: String,
    pub sign1_detached: String,
    pub empty_aad_sign1: String,
    pub empty_payload_detached: String,
    pub sign: String,
    pub counter: String,
    pub counter0: String,
    pub wrong_mgf_signature: Option<String>,
    pub wrong_salt_signature: Option<String>,
}

pub(super) fn fixture() -> Result<Vectors, CoseError> {
    let value: Vectors = serde_json::from_str(include_str!("../../tests/fixtures/rsa.json"))
        .map_err(|_| CoseError::Cbor)?;
    assert_eq!(value.schema, "reallyme.cose.rsa.v1");
    assert_eq!(value.cases.len(), 6);
    Ok(value)
}
pub(super) fn suite(case: &Case) -> Result<wire::CoseSignatureSuite, CoseError> {
    Ok(wire::CoseSignatureSuite {
        registration: wire::CoseSignatureAlgorithm::from(CoseSignatureAlgorithm::from_identifier(
            case.registration,
        )?)
        .into(),
        curve: wire::CoseNamedCurve::Unspecified.into(),
    })
}
pub(super) fn key(vectors: &Vectors, case: &Case) -> Result<wire::CoseSignKeyBinding, CoseError> {
    Ok(wire::CoseSignKeyBinding {
        signature_index: 0,
        suite: field(suite(case)?),
        public_key: hex(&vectors.public_spki).into(),
    })
}
pub(super) fn request(
    vectors: &Vectors,
    case: &Case,
    detached: bool,
) -> Result<wire::CoseRsaSign1VerifyRequest, CoseError> {
    Ok(wire::CoseRsaSign1VerifyRequest {
        encoded: hex(if detached {
            &case.sign1_detached
        } else {
            &case.sign1
        })
        .into(),
        envelope: wire::CoseEnvelopePolicy::Either.into(),
        key: field(key(vectors, case)?),
        allowed_suites: vec![suite(case)?].into(),
        detached_payload: detached.then(|| hex(&vectors.payload).into()),
        external_aad: hex(&vectors.aad).into(),
        expected_kid: Some(b"rsa".to_vec().into()),
    })
}
pub(super) fn sign1(
    protected: &[u8],
    payload: Option<&[u8]>,
    signature: &[u8],
) -> Result<Vec<u8>, CoseError> {
    let value = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected.to_vec()),
            Value::Map(Vec::new()),
            payload.map_or(Value::Null, |bytes| Value::Bytes(bytes.to_vec())),
            Value::Bytes(signature.to_vec()),
        ])),
    );
    encode(value)
}
pub(super) fn encode(value: Value) -> Result<Vec<u8>, CoseError> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded).map_err(|_| CoseError::Cbor)?;
    Ok(encoded)
}
pub(super) fn target(vectors: &Vectors) -> wire::CoseCounterSignatureTarget {
    wire::CoseCounterSignatureTarget {
        encoded: hex(&vectors.counter_target).into(),
        kind: wire::CoseCounterSignatureTargetKind::Sign1.into(),
        envelope: wire::CoseEnvelopePolicy::Either.into(),
        detached_content: None,
    }
}
