// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use zeroize::Zeroizing;

use crate::mac0::{
    cose_verify_mac0_detached, CoseMac0Error, CoseMac0ErrorReason, CoseMac0Limits,
    CoseMac0VerifyRequest, CoseMacAlgorithm, CoseMacKey, VerifiedDetachedCoseMac0,
};

pub(super) const ALGORITHM: CoseMacAlgorithm = CoseMacAlgorithm::Hmac256_256;
pub(super) const KEY: [u8; 32] = [0x11; 32];

#[allow(clippy::expect_used)]
pub(super) fn hex(value: &str) -> Vec<u8> {
    hex::decode(value).expect("fixed test hex must decode")
}

#[allow(clippy::expect_used)]
pub(super) fn encode(value: Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).expect("test CBOR must encode");
    bytes
}

pub(super) fn envelope(
    protected: &[u8],
    unprotected: Value,
    payload: Value,
    tag: &[u8],
) -> Vec<u8> {
    encode(Value::Array(vec![
        Value::Bytes(protected.to_vec()),
        unprotected,
        payload,
        Value::Bytes(tag.to_vec()),
    ]))
}

pub(super) fn detached(protected: &[u8], tag: &[u8]) -> Vec<u8> {
    envelope(protected, Value::Map(vec![]), Value::Null, tag)
}

pub(super) fn request<'a>(
    encoded: &'a [u8],
    payload: &'a [u8],
    aad: &'a [u8],
) -> CoseMac0VerifyRequest<'a> {
    CoseMac0VerifyRequest {
        encoded,
        detached_payload: payload,
        external_aad: aad,
        allowed_algorithms: &[ALGORITHM],
        limits: CoseMac0Limits::default(),
    }
}

pub(super) fn verify(encoded: &[u8]) -> Result<VerifiedDetachedCoseMac0, CoseMac0Error> {
    let key = CoseMacKey::new(ALGORITHM, Zeroizing::new(KEY.to_vec()))?;
    cose_verify_mac0_detached(request(encoded, b"payload", b"aad"), &key)
}

pub(super) fn assert_reason<T>(result: Result<T, CoseMac0Error>, expected: CoseMac0ErrorReason) {
    assert_eq!(result.err().map(CoseMac0Error::reason), Some(expected));
}

/// Test oracle uses Ciborium's generic value encoder, not the production
/// authentication-structure builder. Standards tests separately pin the tags.
#[allow(clippy::expect_used)]
pub(super) fn tag(protected: &[u8], payload: &[u8], aad: &[u8]) -> Vec<u8> {
    let message = encode(Value::Array(vec![
        Value::Text("MAC0".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(aad.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]));
    let key = reallyme_crypto::hmac::HmacKey::from_slice(&KEY).expect("fixed test key");
    reallyme_crypto::hmac::authenticate(ALGORITHM.primitive(), &key, &message)
        .expect("test HMAC must compute")
        .as_bytes()
        .to_vec()
}
