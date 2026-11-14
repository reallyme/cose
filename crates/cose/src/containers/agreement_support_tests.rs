// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{hex, value};
use crate::containers::{
    AgreementEc2EncodingPolicy, AgreementKeyPolicy, ContainerError, ContainerErrorReason as Reason,
    OptionalKeyPolicy, PeerCurve,
};
use ciborium::value::Value;
use serde::Deserialize;

pub(super) const AGREEMENT_CURVES: [PeerCurve; 9] = [
    PeerCurve::P256,
    PeerCurve::P384,
    PeerCurve::P521,
    PeerCurve::BrainpoolP256r1,
    PeerCurve::BrainpoolP320r1,
    PeerCurve::BrainpoolP384r1,
    PeerCurve::BrainpoolP512r1,
    PeerCurve::X25519,
    PeerCurve::X448,
];

#[derive(Deserialize)]
struct Vectors {
    schema: String,
    cases: Vec<Case>,
}

// The shared fixture also contains independent signature answers, consumed by
// peer_tests; agreement tests deliberately deserialize only the public-key data.
#[derive(Deserialize)]
pub(super) struct Case {
    pub curve: i64,
    pub key: String,
    pub compressed: String,
    pub public: String,
}

pub(super) fn cases() -> Result<Vec<Case>, ContainerError> {
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../tests/fixtures/peer-keys.json"))
            .map_err(|_| Reason::Malformed)?;
    assert_eq!(vectors.schema, "reallyme.cose.peer-keys.v1");
    assert_eq!(vectors.cases.len(), 11);
    Ok(vectors.cases)
}

pub(super) fn case(id: i64) -> Result<Case, ContainerError> {
    cases()?
        .into_iter()
        .find(|c| c.curve == id)
        .ok_or(Reason::Key.into())
}

pub(super) fn parameters(case: &Case) -> Result<Vec<(Value, Value)>, ContainerError> {
    let Value::Map(params) = value(&hex(&case.key)) else {
        return Err(Reason::Malformed.into());
    };
    Ok(params)
}

pub(super) fn policy(ec2_encoding: AgreementEc2EncodingPolicy) -> AgreementKeyPolicy<'static> {
    AgreementKeyPolicy {
        allowed_curves: &AGREEMENT_CURVES,
        optional_parameters: OptionalKeyPolicy::Cose,
        ec2_encoding,
    }
}

pub(super) fn ordered(encoded: &[u8]) -> Result<Vec<u8>, ContainerError> {
    let Value::Map(mut params) = value(encoded) else {
        return Err(Reason::Malformed.into());
    };
    params.sort_by_key(|(label, _)| super::support::encode(label.clone()));
    Ok(super::support::map(params))
}
