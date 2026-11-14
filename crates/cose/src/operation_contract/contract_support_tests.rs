// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{
    __buffa::oneof::{
        cose_error::Error, cose_operation_request::Operation, cose_operation_response_v2::Outcome,
        cose_operation_result::Result as Branch,
    },
    CoseErrorReason, CoseOperationRequest, CoseOperationResponseV2, CoseOperationResult,
    CoseSignatureSuite,
};
use crate::CoseError;
use buffa::{EnumValue, Message, MessageField};
use serde::Deserialize;
use zeroize::Zeroizing;

#[allow(clippy::expect_used)]
pub(super) fn hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("independent fixture hex")
}

pub(super) fn request(operation: Operation) -> CoseOperationRequest {
    CoseOperationRequest {
        operation: Some(operation),
    }
}

#[allow(clippy::panic)]
pub(super) fn success(mut response: CoseOperationResponseV2) -> Branch {
    let Some(Outcome::Result(result)) = response.outcome.as_mut() else {
        panic!("expected a successful generated operation");
    };
    match result.result.take() {
        Some(branch) => branch,
        None => panic!("missing generated result"),
    }
}

#[allow(clippy::panic)]
pub(super) fn reason(response: &CoseOperationResponseV2) -> CoseErrorReason {
    let Some(Outcome::Error(error)) = response.outcome.as_ref() else {
        panic!("expected generated error");
    };
    let value = match error.error.as_ref() {
        Some(Error::Primitive(e)) => e.reason,
        Some(Error::Provider(e)) => e.reason,
        Some(Error::Backend(e)) => e.reason,
        None => panic!("missing generated failure branch"),
    };
    match value.as_known() {
        Some(reason) => reason,
        None => panic!("unknown generated failure reason"),
    }
}

pub(super) fn codec_parity(operation: Operation) -> Result<CoseOperationResponseV2, CoseError> {
    codec_parity_with_providers(operation, &crate::api::BuiltinProviders)
}

pub(super) fn codec_parity_with_providers(
    operation: Operation,
    providers: &dyn crate::api::OperationProviders,
) -> Result<CoseOperationResponseV2, CoseError> {
    let request = request(operation);
    let typed = crate::api::execute_with_providers(request.clone(), providers);
    let encoded = Zeroizing::new(request.encode_to_vec());
    let binary = crate::api::execute_protobuf_with_providers(&encoded, providers);
    let decoded = crate::wire::decode_operation_response_for_request(&request, &binary)
        .map_err(|_| CoseError::InvalidFormat)?;
    assert_eq!(typed, decoded);
    let json =
        Zeroizing::new(serde_json::to_string(&request).map_err(|_| CoseError::InvalidFormat)?);
    let json_encoded = crate::api::execute_json_with_providers(&json, providers);
    let json_decoded = crate::wire::decode_operation_response_for_request(&request, &json_encoded)
        .map_err(|_| CoseError::InvalidFormat)?;
    assert_eq!(typed, json_decoded);
    Ok(typed)
}

pub(super) fn suite(algorithm: i64, curve: i64) -> Result<CoseSignatureSuite, CoseError> {
    Ok(CoseSignatureSuite {
        registration: crate::api::contract::CoseSignatureAlgorithm::from(
            crate::CoseSignatureAlgorithm::from_identifier(algorithm)?,
        )
        .into(),
        curve: EnumValue::from(i32::try_from(curve).map_err(|_| CoseError::UnsupportedAlgorithm)?),
    })
}
pub(super) fn field<T>(value: T) -> MessageField<T, buffa::Inline<T>>
where
    T: Message,
{
    MessageField::some(value)
}

#[derive(Deserialize)]
pub(super) struct Cases<T> {
    pub cases: Vec<T>,
}
#[derive(Deserialize)]
pub(super) struct KeyCase {
    pub curve: i64,
    pub key: String,
    pub compressed: String,
    pub public: String,
}
pub(super) fn keys() -> Result<Vec<KeyCase>, CoseError> {
    serde_json::from_str::<Cases<KeyCase>>(include_str!("../../tests/fixtures/peer-keys.json"))
        .map(|v| v.cases)
        .map_err(|_| CoseError::Cbor)
}

pub(super) fn result(branch: Branch) -> CoseOperationResult {
    CoseOperationResult {
        result: Some(branch),
    }
}

pub(super) fn capability(
    handle: u64,
    kind: crate::api::contract::CoseProviderKind,
) -> MessageField<
    crate::api::contract::CoseProviderCapability,
    buffa::Inline<crate::api::contract::CoseProviderCapability>,
> {
    if handle == 0 {
        return MessageField::none();
    }
    MessageField::some(crate::api::contract::CoseProviderCapability {
        handle,
        kind: kind.into(),
    })
}
