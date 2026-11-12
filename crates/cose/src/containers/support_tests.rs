// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::containers::{
    CertificateHeaders, CertificateSelection, CertificateValidator, ContainerContent,
    ContainerError, ContainerErrorReason as Reason, ContainerLimits, ContainerPolicy,
    ContainerProfile, ContainerPurpose, ContainerVerifyRequest, CryptoVerificationKey,
    EnvelopePolicy, SignatureSuite,
};
use crate::iso18013::{Iso18013SignatureAlgorithm, Iso18013SignatureCurve};
use ciborium::value::Value;
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Vectors {
    pub schema: String,
    pub certificate_a: String,
    pub certificate_b: String,
    pub certificate_a_sha256: String,
    pub cases: Vec<Case>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Case {
    pub id: String,
    pub algorithm: i64,
    pub curve: i64,
    pub public_key: String,
    pub protected: String,
    pub unprotected: String,
    pub payload: String,
    pub signature: String,
    pub structure: String,
    pub encoded: String,
}

#[allow(clippy::expect_used)]
pub(super) fn fixtures() -> Vectors {
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../tests/fixtures/containers.json"))
            .expect("synthetic fixture");
    assert_eq!(vectors.schema, "reallyme.cose.containers.v1");
    assert_eq!(vectors.cases.len(), 10);
    vectors
}
#[allow(clippy::expect_used)]
pub(super) fn hex(input: &str) -> Vec<u8> {
    hex::decode(input).expect("fixture hex")
}
#[allow(clippy::expect_used)]
pub(super) fn encode(value: Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).expect("test CBOR");
    bytes
}
#[allow(clippy::expect_used)]
pub(super) fn value(bytes: &[u8]) -> Value {
    ciborium::de::from_reader(bytes).expect("fixture CBOR")
}
pub(super) fn int(value: i64) -> Value {
    Value::Integer(value.into())
}
pub(super) fn map(values: Vec<(Value, Value)>) -> Vec<u8> {
    encode(Value::Map(values))
}
pub(super) fn envelope(
    protected: &[u8],
    unprotected: &[u8],
    payload: Option<&[u8]>,
    signature: &[u8],
) -> Vec<u8> {
    encode(Value::Array(vec![
        Value::Bytes(protected.to_vec()),
        value(unprotected),
        payload.map_or(Value::Null, |p| Value::Bytes(p.to_vec())),
        Value::Bytes(signature.to_vec()),
    ]))
}
pub(super) fn suite(case: &Case) -> Result<SignatureSuite, ContainerError> {
    if case.algorithm == -9 {
        return SignatureSuite::modern(crate::CoseSignatureAlgorithm::Esp256);
    }
    SignatureSuite::iso(
        Iso18013SignatureAlgorithm::from_identifier(case.algorithm)?,
        Iso18013SignatureCurve::from_identifier(case.curve)?,
    )
}
pub(super) fn key(case: &Case) -> Result<CryptoVerificationKey, ContainerError> {
    CryptoVerificationKey::new(
        suite(case)?,
        Zeroizing::new(hex(&case.public_key)),
        [0x42; 32],
    )
}
pub(super) fn policy(case: &Case) -> ContainerPolicy {
    let purpose = match case.id.as_str() {
        "reader-all" => ContainerPurpose::ReaderAuthenticationAll,
        "reader" => ContainerPurpose::ReaderAuthentication,
        "device" => ContainerPurpose::DeviceAuthentication,
        "revocation" => ContainerPurpose::MsoRevocation,
        "vical" => ContainerPurpose::Vical,
        "rical" => ContainerPurpose::Rical,
        "strict-modern" => ContainerPurpose::Generic,
        _ => ContainerPurpose::IssuerMso,
    };
    let profile = match case.id.as_str() {
        "issuer-2021" => ContainerProfile::Iso2021,
        "strict-modern" => ContainerProfile::Rfc9360,
        _ => ContainerProfile::IsoEdition2Dis,
    };
    ContainerPolicy {
        profile,
        purpose,
        envelope: EnvelopePolicy::Untagged,
    }
}
pub(super) fn request<'a>(
    encoded: &'a [u8],
    payload: &'a [u8],
    policy: ContainerPolicy,
    suites: &'a [SignatureSuite],
) -> ContainerVerifyRequest<'a> {
    let detached = matches!(
        policy.purpose,
        ContainerPurpose::ReaderAuthentication
            | ContainerPurpose::ReaderAuthenticationAll
            | ContainerPurpose::DeviceAuthentication
    );
    ContainerVerifyRequest {
        encoded,
        content: if detached {
            ContainerContent::Detached(payload)
        } else {
            ContainerContent::Attached
        },
        external_aad: &[],
        policy,
        allowed_suites: suites,
        limits: ContainerLimits::default(),
    }
}
pub(super) struct Trust<'a> {
    pub key: &'a CryptoVerificationKey,
    pub certificate: &'a [u8],
}
impl CertificateValidator for Trust<'_> {
    fn resolve(
        &self,
        _headers: &CertificateHeaders<'_>,
        _algorithm: i64,
    ) -> Result<CertificateSelection<'_>, ContainerError> {
        Ok(CertificateSelection {
            key: self.key,
            end_entity_der: self.certificate,
        })
    }
}
pub(super) fn assert_error<T>(result: Result<T, ContainerError>, reason: Reason) {
    assert_eq!(result.err().map(ContainerError::reason), Some(reason));
}
