// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Deterministically regenerates the committed COSE maintenance vectors.
//!
//! The separate `reallyme-cose-vector-audit` binary verifies the resulting
//! bytes with direct RustCrypto dependencies, so regeneration and audit do not
//! share the production COSE parser, verifier, or ML-KEM decryptor.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use reallyme_cose::{cose_sign1, cose_sign1_detached, Algorithm};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod ml_kem_encrypt;
mod pq;

const VECTOR_PATH: &str = "vectors/cose-sign1.json";
const ED25519_ALGORITHM: i64 = -19;

#[derive(Debug, Error)]
enum RegenerateError {
    #[error("vector file could not be read")]
    Read,
    #[error("vector JSON could not be decoded")]
    JsonDecode,
    #[error("vector JSON could not be encoded")]
    JsonEncode,
    #[error("vector file could not be written")]
    Write,
    #[error("vector case is missing")]
    MissingCase,
    #[error("vector hex is invalid")]
    Hex,
    #[error("vector algorithm is unsupported")]
    Algorithm,
    #[error("COSE signing failed")]
    Sign,
    #[error("COSE encryption vector generation failed")]
    Encrypt,
    #[error("post-quantum key and Sign1 vector generation failed")]
    PostQuantum,
    #[error("CBOR decoding failed")]
    CborDecode,
    #[error("CBOR encoding failed")]
    CborEncode,
    #[error("COSE_Sign1 shape is invalid")]
    Sign1Shape,
    #[error("Ed25519 private seed has the wrong length")]
    SeedLength,
    #[error("ECDSA signature has the wrong width")]
    SignatureWidth,
    #[error("integer conversion failed")]
    IntegerConversion,
}

#[derive(Debug, Deserialize, Serialize)]
struct Suite {
    schema: String,
    suite: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Case {
    id: String,
    operation: String,
    algorithm: String,
    kid_hex: String,
    public_key_hex: String,
    private_key_seed_hex: String,
    payload_hex: String,
    cose_sign1_hex: String,
    expected_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provenance: Option<Provenance>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Provenance {
    NodeOpenSslRfc8032,
}

struct Bases {
    ed_attached: Vec<u8>,
    ed_detached: Vec<u8>,
    p256_attached: Vec<u8>,
    p256_detached: Vec<u8>,
    p384_attached: Vec<u8>,
    p384_detached: Vec<u8>,
    p521_attached: Vec<u8>,
    p521_detached: Vec<u8>,
    secp256k1_attached: Vec<u8>,
    secp256k1_detached: Vec<u8>,
}

fn main() -> Result<(), RegenerateError> {
    regenerate_sign1()?;
    ml_kem_encrypt::regenerate().map_err(|_| RegenerateError::Encrypt)?;
    pq::regenerate().map_err(|_| RegenerateError::PostQuantum)
}

fn regenerate_sign1() -> Result<(), RegenerateError> {
    let root = repository_root();
    let path = root.join(VECTOR_PATH);
    let input = fs::read(&path).map_err(|_| RegenerateError::Read)?;
    let mut suite: Suite =
        serde_json::from_slice(&input).map_err(|_| RegenerateError::JsonDecode)?;
    let bases = build_bases(&suite)?;

    for case in &mut suite.cases {
        let bytes = regenerate_case(case, &bases)?;
        case.cose_sign1_hex = hex::encode(bytes);
    }

    let mut output = serde_json::to_vec_pretty(&suite).map_err(|_| RegenerateError::JsonEncode)?;
    output.push(b'\n');
    fs::write(path, output).map_err(|_| RegenerateError::Write)
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn build_bases(suite: &Suite) -> Result<Bases, RegenerateError> {
    Ok(Bases {
        ed_attached: sign_case(find_case(suite, "cose-sign1-ed25519-attached")?, false)?,
        ed_detached: sign_case(find_case(suite, "cose-sign1-ed25519-detached")?, true)?,
        p256_attached: sign_case(find_case(suite, "cose-sign1-es256-attached")?, false)?,
        p256_detached: sign_case(find_case(suite, "cose-sign1-es256-detached")?, true)?,
        p384_attached: sign_case(find_case(suite, "cose-sign1-es384-attached")?, false)?,
        p384_detached: sign_case(find_case(suite, "cose-sign1-es384-detached")?, true)?,
        p521_attached: sign_case(find_case(suite, "cose-sign1-es512-attached")?, false)?,
        p521_detached: sign_case(find_case(suite, "cose-sign1-es512-detached")?, true)?,
        secp256k1_attached: sign_case(find_case(suite, "cose-sign1-es256k-attached")?, false)?,
        secp256k1_detached: sign_case(find_case(suite, "cose-sign1-es256k-detached")?, true)?,
    })
}

fn find_case<'a>(suite: &'a Suite, id: &str) -> Result<&'a Case, RegenerateError> {
    suite
        .cases
        .iter()
        .find(|case| case.id == id)
        .ok_or(RegenerateError::MissingCase)
}

fn sign_case(case: &Case, detached: bool) -> Result<Vec<u8>, RegenerateError> {
    let algorithm = parse_algorithm(&case.algorithm)?;
    let private_key = decode_hex(&case.private_key_seed_hex)?;
    let kid = decode_hex(&case.kid_hex)?;
    let payload = decode_hex(&case.payload_hex)?;
    let encoded = if detached {
        cose_sign1_detached(algorithm, &payload, &private_key, Some(&kid))
    } else {
        cose_sign1(algorithm, &payload, &private_key, Some(&kid))
    }
    .map_err(|_| RegenerateError::Sign)?;
    Ok(encoded.to_vec())
}

fn regenerate_case(case: &Case, bases: &Bases) -> Result<Vec<u8>, RegenerateError> {
    let bytes = match case.id.as_str() {
        "cose-sign1-ed25519-attached" => bases.ed_attached.clone(),
        "cose-sign1-ed25519-detached"
        | "cose-sign1-ed25519-detached-wrong-payload"
        | "cose-sign1-ed25519-detached-wrong-kid"
        | "cose-sign1-ed25519-detached-as-attached" => bases.ed_detached.clone(),
        "cose-sign1-es256-attached" => bases.p256_attached.clone(),
        "cose-sign1-es256-detached" | "cose-sign1-es256-detached-wrong-payload" => {
            bases.p256_detached.clone()
        }
        "cose-sign1-es256-der-signature" => ecdsa_der_variant(&bases.p256_attached)?,
        "cose-sign1-es384-attached" => bases.p384_attached.clone(),
        "cose-sign1-es384-detached" => bases.p384_detached.clone(),
        "cose-sign1-es512-attached" => bases.p521_attached.clone(),
        "cose-sign1-es512-detached" => bases.p521_detached.clone(),
        "cose-sign1-es256k-attached" => bases.secp256k1_attached.clone(),
        "cose-sign1-es256k-detached" => bases.secp256k1_detached.clone(),
        "cose-sign1-ed25519-tampered-signature" => tampered_variant(&bases.ed_attached)?,
        "cose-sign1-ed25519-unsupported-alg" | "cose-sign1-ed25519-missing-alg" => {
            decode_hex(&case.cose_sign1_hex)?
        }
        "cose-sign1-ed25519-crit-header" => critical_header_variant(case)?,
        "cose-sign1-ed25519-unprotected-kid" => unprotected_kid_variant(&bases.ed_attached)?,
        "cose-sign1-ed25519-attached-as-detached" => bases.ed_attached.clone(),
        "cose-sign1-ed25519-reordered-protected-header" => reordered_header_variant(case)?,
        "cose-sign1-ed25519-tagged-root" => tagged_variant(&bases.ed_attached)?,
        // This fixed signature is produced by Node's OpenSSL-backed Ed25519
        // implementation. Regeneration must preserve the external oracle.
        "cose-sign1-ed25519-node-openssl" => decode_hex(&case.cose_sign1_hex)?,
        _ => return Err(RegenerateError::MissingCase),
    };
    Ok(bytes)
}

fn critical_header_variant(case: &Case) -> Result<Vec<u8>, RegenerateError> {
    let kid = decode_hex(&case.kid_hex)?;
    let payload = decode_hex(&case.payload_hex)?;
    let seed = decode_hex(&case.private_key_seed_hex)?;
    let protected = Value::Map(vec![
        (
            Value::Integer(1_i64.into()),
            Value::Integer(ED25519_ALGORITHM.into()),
        ),
        (
            Value::Integer(2_i64.into()),
            Value::Array(vec![Value::Integer(1_i64.into())]),
        ),
        (Value::Integer(4_i64.into()), Value::Bytes(kid)),
    ]);
    signed_ed25519_value(protected, Value::Map(Vec::new()), Some(payload), &seed)
}

fn reordered_header_variant(case: &Case) -> Result<Vec<u8>, RegenerateError> {
    let kid = decode_hex(&case.kid_hex)?;
    let payload = decode_hex(&case.payload_hex)?;
    let seed = decode_hex(&case.private_key_seed_hex)?;
    let protected = Value::Map(vec![
        (Value::Integer(4_i64.into()), Value::Bytes(kid)),
        (
            Value::Integer(1_i64.into()),
            Value::Integer(ED25519_ALGORITHM.into()),
        ),
    ]);
    signed_ed25519_value(protected, Value::Map(Vec::new()), Some(payload), &seed)
}

fn signed_ed25519_value(
    protected: Value,
    unprotected: Value,
    payload: Option<Vec<u8>>,
    seed: &[u8],
) -> Result<Vec<u8>, RegenerateError> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| RegenerateError::SeedLength)?;
    let protected_bytes = encode_cbor(&protected)?;
    let signing_payload = payload.as_deref().ok_or(RegenerateError::Sign1Shape)?;
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_owned()),
        Value::Bytes(protected_bytes.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(signing_payload.to_vec()),
    ]);
    let signature = SigningKey::from_bytes(&seed)
        .sign(&encode_cbor(&sig_structure)?)
        .to_bytes()
        .to_vec();
    encode_cbor(&Value::Array(vec![
        Value::Bytes(protected_bytes),
        unprotected,
        payload.map_or(Value::Null, Value::Bytes),
        Value::Bytes(signature),
    ]))
}

fn unprotected_kid_variant(base: &[u8]) -> Result<Vec<u8>, RegenerateError> {
    let mut value = decode_cbor(base)?;
    let array = value.as_array_mut().ok_or(RegenerateError::Sign1Shape)?;
    let unprotected = array
        .get_mut(1)
        .and_then(Value::as_map_mut)
        .ok_or(RegenerateError::Sign1Shape)?;
    unprotected.push((
        Value::Integer(4_i64.into()),
        Value::Bytes(b"shadow-kid".to_vec()),
    ));
    encode_cbor(&value)
}

fn tampered_variant(base: &[u8]) -> Result<Vec<u8>, RegenerateError> {
    let mut value = decode_cbor(base)?;
    let signature = value
        .as_array_mut()
        .and_then(|array| array.get_mut(3))
        .and_then(Value::as_bytes_mut)
        .ok_or(RegenerateError::Sign1Shape)?;
    let last = signature
        .last_mut()
        .ok_or(RegenerateError::SignatureWidth)?;
    *last ^= 0xff;
    encode_cbor(&value)
}

fn ecdsa_der_variant(base: &[u8]) -> Result<Vec<u8>, RegenerateError> {
    let mut value = decode_cbor(base)?;
    let signature = value
        .as_array_mut()
        .and_then(|array| array.get_mut(3))
        .and_then(Value::as_bytes_mut)
        .ok_or(RegenerateError::Sign1Shape)?;
    *signature = raw_p256_to_der(signature)?;
    encode_cbor(&value)
}

fn raw_p256_to_der(raw: &[u8]) -> Result<Vec<u8>, RegenerateError> {
    if raw.len() != 64 {
        return Err(RegenerateError::SignatureWidth);
    }
    let r = der_integer(&raw[..32])?;
    let s = der_integer(&raw[32..])?;
    let content_len = r
        .len()
        .checked_add(s.len())
        .ok_or(RegenerateError::IntegerConversion)?;
    let content_len = u8::try_from(content_len).map_err(|_| RegenerateError::IntegerConversion)?;
    let mut der = Vec::with_capacity(usize::from(content_len) + 2);
    der.extend_from_slice(&[0x30, content_len]);
    der.extend_from_slice(&r);
    der.extend_from_slice(&s);
    Ok(der)
}

fn der_integer(scalar: &[u8]) -> Result<Vec<u8>, RegenerateError> {
    let first_nonzero = scalar
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(scalar.len());
    let body = &scalar[first_nonzero..];
    if body.is_empty() {
        return Err(RegenerateError::SignatureWidth);
    }
    let padding = usize::from(body[0] & 0x80 != 0);
    let length = body
        .len()
        .checked_add(padding)
        .ok_or(RegenerateError::IntegerConversion)?;
    let length = u8::try_from(length).map_err(|_| RegenerateError::IntegerConversion)?;
    let mut encoded = Vec::with_capacity(usize::from(length) + 2);
    encoded.extend_from_slice(&[0x02, length]);
    if padding == 1 {
        encoded.push(0);
    }
    encoded.extend_from_slice(body);
    Ok(encoded)
}

fn tagged_variant(base: &[u8]) -> Result<Vec<u8>, RegenerateError> {
    encode_cbor(&Value::Tag(18, Box::new(decode_cbor(base)?)))
}

fn parse_algorithm(value: &str) -> Result<Algorithm, RegenerateError> {
    match value {
        "Ed25519" => Ok(Algorithm::Ed25519),
        "P256" => Ok(Algorithm::P256),
        "P384" => Ok(Algorithm::P384),
        "P521" => Ok(Algorithm::P521),
        "Secp256k1" => Ok(Algorithm::Secp256k1),
        _ => Err(RegenerateError::Algorithm),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, RegenerateError> {
    hex::decode(value).map_err(|_| RegenerateError::Hex)
}

fn decode_cbor(bytes: &[u8]) -> Result<Value, RegenerateError> {
    ciborium::de::from_reader(Cursor::new(bytes)).map_err(|_| RegenerateError::CborDecode)
}

fn encode_cbor(value: &Value) -> Result<Vec<u8>, RegenerateError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, Cursor::new(&mut bytes))
        .map_err(|_| RegenerateError::CborEncode)?;
    Ok(bytes)
}
