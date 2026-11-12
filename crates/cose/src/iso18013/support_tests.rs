// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::iso18013::{
    Iso18013Sign1Content, Iso18013Sign1Limits, Iso18013Sign1Request, Iso18013SignatureAlgorithm,
    Iso18013SignatureCurve, Iso18013SignatureSuite,
};
use crate::CoseError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Vectors {
    pub(super) schema: String,
    pub(super) oracle: String,
    pub(super) cases: Vec<Vector>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Vector {
    pub(super) id: String,
    pub(super) algorithm: i64,
    pub(super) curve: i64,
    pub(super) public_key_hex: String,
    pub(super) wrong_public_key_hex: String,
    pub(super) cose_key_hex: String,
    pub(super) protected_hex: String,
    pub(super) payload_hex: String,
    pub(super) signature_hex: String,
    pub(super) sig_structure_hex: String,
    pub(super) attached_hex: String,
    pub(super) detached_hex: String,
}

pub(super) fn vectors() -> Result<Vec<Vector>, CoseError> {
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../tests/fixtures/iso18013-sign1.json"))
            .map_err(|_| CoseError::Cbor)?;
    assert_eq!(vectors.schema, "reallyme.cose.iso18013.sign1.vectors.v1");
    assert!(vectors.oracle.contains("OpenSSL"));
    assert_eq!(vectors.cases.len(), 10);
    assert!(vectors.cases.iter().all(|case| !case.id.is_empty()));
    Ok(vectors.cases)
}

#[allow(clippy::expect_used)]
pub(super) fn hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("fixed vector hex must decode")
}

pub(super) fn suite(vector: &Vector) -> Result<Iso18013SignatureSuite, CoseError> {
    Iso18013SignatureSuite::new(
        Iso18013SignatureAlgorithm::from_identifier(vector.algorithm)?,
        Iso18013SignatureCurve::from_identifier(vector.curve)?,
    )
}

pub(super) fn request<'a>(
    encoded: &'a [u8],
    content: Iso18013Sign1Content<'a>,
    allowed_suites: &'a [Iso18013SignatureSuite],
) -> Iso18013Sign1Request<'a> {
    Iso18013Sign1Request {
        encoded,
        content,
        allowed_suites,
        limits: Iso18013Sign1Limits::default(),
    }
}

pub(super) fn assert_error<T>(result: Result<T, CoseError>, error: CoseError) {
    assert_eq!(result.err(), Some(error));
}

#[allow(clippy::expect_used)]
pub(super) fn encode(value: Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).expect("test value must encode");
    bytes
}

pub(super) fn envelope(
    protected: &[u8],
    unprotected: Value,
    payload: Option<&[u8]>,
    signature: &[u8],
) -> Vec<u8> {
    encode(Value::Array(vec![
        Value::Bytes(protected.to_vec()),
        unprotected,
        payload.map_or(Value::Null, |bytes| Value::Bytes(bytes.to_vec())),
        Value::Bytes(signature.to_vec()),
    ]))
}

pub(super) fn key(vector: &Vector) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(hex(&vector.public_key_hex))
}
