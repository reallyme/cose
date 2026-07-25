// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Deterministic PQ COSE_Key, Multikey, and COSE_Sign1 vector generation.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use ciborium::value::Value;
use ml_dsa::{KeyExport, Keypair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed, SigningKey};
use reallyme_cose::{
    cose_key_from_public_bytes, cose_key_to_multikey, cose_key_to_vec, cose_sign1,
    derive_kid_from_cose_key_public, Algorithm,
};
use serde::Serialize;
use thiserror::Error;

const SIGN1_PATH: &str = "vectors/cose-sign1-pq.json";
const KEY_PATH: &str = "vectors/cose-key-pq.json";

const ML_DSA_44_SEED: [u8; 32] = [
    0x44, 0x91, 0x37, 0xf7, 0x36, 0xf5, 0xf5, 0xa3, 0x5e, 0xb9, 0xf3, 0x7c, 0x1c, 0x88, 0xc2, 0xa0,
    0xbc, 0xf1, 0x8e, 0x75, 0x7f, 0xfb, 0x92, 0x85, 0xab, 0x2c, 0x4c, 0x26, 0xc1, 0x5c, 0x55, 0xf1,
];
const ML_DSA_65_SEED: [u8; 32] = [
    0x65, 0x91, 0x37, 0xf7, 0x36, 0xf5, 0xf5, 0xa3, 0x5e, 0xb9, 0xf3, 0x7c, 0x1c, 0x88, 0xc2, 0xa0,
    0xbc, 0xf1, 0x8e, 0x75, 0x7f, 0xfb, 0x92, 0x85, 0xab, 0x2c, 0x4c, 0x26, 0xc1, 0x5c, 0x55, 0xf1,
];
const ML_DSA_87_SEED: [u8; 32] = [
    0x1e, 0x91, 0x37, 0xf7, 0x36, 0xf5, 0xf5, 0xa3, 0x5e, 0xb9, 0xf3, 0x7c, 0x1c, 0x88, 0xc2, 0xa0,
    0xbc, 0xf1, 0x8e, 0x75, 0x7f, 0xfb, 0x92, 0x85, 0xab, 0x2c, 0x4c, 0x26, 0xc1, 0x5c, 0x55, 0xf1,
];

#[derive(Debug, Error)]
pub(super) enum GenerateError {
    #[error("PQ vector key generation failed")]
    KeyGeneration,
    #[error("PQ vector COSE conversion failed")]
    Cose,
    #[error("PQ vector serialization failed")]
    Json,
    #[error("PQ vector file could not be written")]
    Write,
    #[error("PQ COSE_Sign1 fixture could not be decoded")]
    CborDecode,
    #[error("PQ COSE_Sign1 fixture could not be encoded")]
    CborEncode,
    #[error("PQ COSE_Sign1 fixture has an invalid shape")]
    Sign1Shape,
}

#[derive(Serialize)]
struct Suite<T> {
    schema: &'static str,
    suite: &'static str,
    note: &'static str,
    cases: Vec<T>,
}

#[derive(Serialize)]
struct Sign1Case {
    id: String,
    operation: &'static str,
    algorithm: &'static str,
    kid_hex: String,
    public_key_hex: String,
    private_key_seed_hex: String,
    payload_hex: String,
    cose_sign1_hex: String,
    expected_error: Option<&'static str>,
}

#[derive(Serialize)]
struct KeyCase {
    id: String,
    algorithm: &'static str,
    private_key_seed_hex: String,
    public_key_hex: String,
    cose_key_hex: String,
    multikey: String,
}

pub(super) fn regenerate() -> Result<(), GenerateError> {
    let mut sign1_cases = Vec::with_capacity(7);
    let mut key_cases = Vec::with_capacity(6);

    add_ml_dsa::<MlDsa44>(
        Algorithm::MlDsa44,
        "ML-DSA-44",
        &ML_DSA_44_SEED,
        &mut sign1_cases,
        &mut key_cases,
    )?;
    add_ml_dsa::<MlDsa65>(
        Algorithm::MlDsa65,
        "ML-DSA-65",
        &ML_DSA_65_SEED,
        &mut sign1_cases,
        &mut key_cases,
    )?;
    add_ml_dsa::<MlDsa87>(
        Algorithm::MlDsa87,
        "ML-DSA-87",
        &ML_DSA_87_SEED,
        &mut sign1_cases,
        &mut key_cases,
    )?;

    add_ml_kem(Algorithm::MlKem512, "ML-KEM-512", 0x51, &mut key_cases)?;
    add_ml_kem(Algorithm::MlKem768, "ML-KEM-768", 0x76, &mut key_cases)?;
    add_ml_kem(Algorithm::MlKem1024, "ML-KEM-1024", 0xa1, &mut key_cases)?;

    write_suite(
        SIGN1_PATH,
        &Suite {
            schema: "reallyme.cose.conformance.cose_sign1_pq.v1",
            suite: "cose-sign1-pq",
            note: "Deterministic ML-DSA COSE_Sign1 fixtures with independent COSE-layer parsing and direct primitive verification by the vector auditor.",
            cases: sign1_cases,
        },
    )?;
    write_suite(
        KEY_PATH,
        &Suite {
            schema: "reallyme.cose.conformance.cose_key_pq.v1",
            suite: "cose-key-pq",
            note: "ReallyMe AKP COSE_Key and Multikey fixtures for ML-DSA and the pre-IANA ReallyMe ML-KEM COSE profile.",
            cases: key_cases,
        },
    )
}

fn add_ml_dsa<P: MlDsaParams>(
    algorithm: Algorithm,
    name: &'static str,
    seed_bytes: &[u8; 32],
    sign1_cases: &mut Vec<Sign1Case>,
    key_cases: &mut Vec<KeyCase>,
) -> Result<(), GenerateError> {
    let seed = Seed::try_from(seed_bytes.as_slice()).map_err(|_| GenerateError::KeyGeneration)?;
    let signing_key = SigningKey::<P>::from_seed(&seed);
    let public = signing_key.verifying_key().to_bytes().to_vec();
    let cose_key =
        cose_key_from_public_bytes(algorithm, &public).map_err(|_| GenerateError::Cose)?;
    let kid = derive_kid_from_cose_key_public(&cose_key).map_err(|_| GenerateError::Cose)?;
    let payload = format!("ReallyMe independent {name} COSE_Sign1 vector").into_bytes();
    let sign1 =
        cose_sign1(algorithm, &payload, seed_bytes, Some(&kid)).map_err(|_| GenerateError::Cose)?;

    let kid_hex = hex::encode(&kid);
    let public_key_hex = hex::encode(&public);
    let private_key_seed_hex = hex::encode(seed_bytes);
    let payload_hex = hex::encode(&payload);

    sign1_cases.push(Sign1Case {
        id: format!("cose-sign1-{}-attached", name.to_ascii_lowercase()),
        operation: "verify_attached",
        algorithm: name,
        kid_hex: kid_hex.clone(),
        public_key_hex: public_key_hex.clone(),
        private_key_seed_hex: private_key_seed_hex.clone(),
        payload_hex: payload_hex.clone(),
        cose_sign1_hex: hex::encode(&sign1),
        expected_error: None,
    });
    if algorithm == Algorithm::MlDsa44 {
        add_ml_dsa_negative_cases(
            name,
            &kid_hex,
            &public_key_hex,
            &private_key_seed_hex,
            &payload,
            &sign1,
            sign1_cases,
        )?;
    }
    key_cases.push(key_case(algorithm, name, seed_bytes, &public)?);
    Ok(())
}

fn add_ml_dsa_negative_cases(
    name: &'static str,
    kid_hex: &str,
    public_key_hex: &str,
    private_key_seed_hex: &str,
    payload: &[u8],
    sign1: &[u8],
    cases: &mut Vec<Sign1Case>,
) -> Result<(), GenerateError> {
    for (suffix, mutation, expected_error) in [
        (
            "tampered-signature",
            Sign1Mutation::TamperSignature,
            "InvalidSignature",
        ),
        (
            "wrong-payload",
            Sign1Mutation::TamperPayload,
            "InvalidSignature",
        ),
        (
            "truncated-signature",
            Sign1Mutation::TruncateSignature,
            "InvalidSignatureEncoding",
        ),
        (
            "extended-signature",
            Sign1Mutation::ExtendSignature,
            "InvalidSignatureEncoding",
        ),
    ] {
        let (mutated, effective_payload) = mutate_sign1(sign1, payload, mutation)?;
        cases.push(Sign1Case {
            id: format!("cose-sign1-{}-{suffix}", name.to_ascii_lowercase()),
            operation: "verify_attached",
            algorithm: name,
            kid_hex: kid_hex.to_owned(),
            public_key_hex: public_key_hex.to_owned(),
            private_key_seed_hex: private_key_seed_hex.to_owned(),
            payload_hex: hex::encode(effective_payload),
            cose_sign1_hex: hex::encode(mutated),
            expected_error: Some(expected_error),
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Sign1Mutation {
    TamperSignature,
    TamperPayload,
    TruncateSignature,
    ExtendSignature,
}

fn mutate_sign1(
    encoded: &[u8],
    original_payload: &[u8],
    mutation: Sign1Mutation,
) -> Result<(Vec<u8>, Vec<u8>), GenerateError> {
    let mut value: Value =
        ciborium::de::from_reader(Cursor::new(encoded)).map_err(|_| GenerateError::CborDecode)?;
    let array = match &mut value {
        Value::Array(array) if array.len() == 4 => array,
        _ => return Err(GenerateError::Sign1Shape),
    };
    let mut effective_payload = original_payload.to_vec();
    match mutation {
        Sign1Mutation::TamperPayload => {
            let payload = match array.get_mut(2) {
                Some(Value::Bytes(payload)) => payload,
                _ => return Err(GenerateError::Sign1Shape),
            };
            let first = payload.first_mut().ok_or(GenerateError::Sign1Shape)?;
            *first ^= 1;
            effective_payload = payload.clone();
        }
        Sign1Mutation::TamperSignature
        | Sign1Mutation::TruncateSignature
        | Sign1Mutation::ExtendSignature => {
            let signature = match array.get_mut(3) {
                Some(Value::Bytes(signature)) => signature,
                _ => return Err(GenerateError::Sign1Shape),
            };
            match mutation {
                Sign1Mutation::TamperSignature => {
                    let last = signature.last_mut().ok_or(GenerateError::Sign1Shape)?;
                    *last ^= 1;
                }
                Sign1Mutation::TruncateSignature => {
                    signature.pop().ok_or(GenerateError::Sign1Shape)?;
                }
                Sign1Mutation::ExtendSignature => signature.push(0),
                Sign1Mutation::TamperPayload => return Err(GenerateError::Sign1Shape),
            }
        }
    }
    let mut output = Vec::new();
    ciborium::ser::into_writer(&value, &mut output).map_err(|_| GenerateError::CborEncode)?;
    Ok((output, effective_payload))
}

fn add_ml_kem(
    algorithm: Algorithm,
    name: &'static str,
    marker: u8,
    key_cases: &mut Vec<KeyCase>,
) -> Result<(), GenerateError> {
    let seed_bytes = patterned::<64>(marker);
    let seed =
        ml_kem::Seed::try_from(seed_bytes.as_slice()).map_err(|_| GenerateError::KeyGeneration)?;
    let public = match algorithm {
        Algorithm::MlKem512 => ml_kem::ml_kem_512::DecapsulationKey::from_seed(seed)
            .encapsulation_key()
            .to_bytes()
            .to_vec(),
        Algorithm::MlKem768 => ml_kem::ml_kem_768::DecapsulationKey::from_seed(seed)
            .encapsulation_key()
            .to_bytes()
            .to_vec(),
        Algorithm::MlKem1024 => ml_kem::ml_kem_1024::DecapsulationKey::from_seed(seed)
            .encapsulation_key()
            .to_bytes()
            .to_vec(),
        _ => return Err(GenerateError::KeyGeneration),
    };
    key_cases.push(key_case(algorithm, name, &seed_bytes, &public)?);
    Ok(())
}

fn key_case(
    algorithm: Algorithm,
    name: &'static str,
    seed: &[u8],
    public: &[u8],
) -> Result<KeyCase, GenerateError> {
    let key = cose_key_from_public_bytes(algorithm, public).map_err(|_| GenerateError::Cose)?;
    Ok(KeyCase {
        id: format!("cose-key-{}-public", name.to_ascii_lowercase()),
        algorithm: name,
        private_key_seed_hex: hex::encode(seed),
        public_key_hex: hex::encode(public),
        cose_key_hex: hex::encode(cose_key_to_vec(&key).map_err(|_| GenerateError::Cose)?),
        multikey: cose_key_to_multikey(&key)
            .map_err(|_| GenerateError::Cose)?
            .to_string(),
    })
}

fn write_suite(path: &str, suite: &impl Serialize) -> Result<(), GenerateError> {
    let mut output = serde_json::to_vec_pretty(suite).map_err(|_| GenerateError::Json)?;
    output.push(b'\n');
    fs::write(repository_root().join(path), output).map_err(|_| GenerateError::Write)
}

fn patterned<const N: usize>(marker: u8) -> [u8; N] {
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = u8::try_from(index % 251).unwrap_or(0);
        *byte = marker.wrapping_add(offset);
    }
    bytes
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
