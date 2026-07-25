// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! COSE-layer audit for ML-DSA and ML-KEM vectors.

use std::collections::HashSet;
use std::io::Cursor;
use std::path::Path;

use ciborium::value::Value;
use ml_dsa::{
    EncodedVerifyingKey, KeyExport, Keypair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed,
    Signature, SigningKey, Verifier, VerifyingKey,
};
use serde::Deserialize;

use super::{
    attach_case, audit_multikey, audit_unique_id, decode_hex, encode_cbor, ensure, general,
    map_get, read_json, AuditContext, AuditReason, AuditResult,
};

const SIGN1_FILE: &str = "vectors/cose-sign1-pq.json";
const KEY_FILE: &str = "vectors/cose-key-pq.json";

pub(super) struct Summary {
    pub(super) sign1_cases: usize,
    pub(super) key_cases: usize,
}

#[derive(Deserialize)]
struct Suite<T> {
    cases: Vec<T>,
}

#[derive(Deserialize)]
struct Sign1Case {
    id: String,
    operation: String,
    algorithm: String,
    kid_hex: String,
    public_key_hex: String,
    private_key_seed_hex: String,
    payload_hex: String,
    cose_sign1_hex: String,
    expected_error: Option<String>,
}

#[derive(Deserialize)]
struct KeyCase {
    id: String,
    algorithm: String,
    private_key_seed_hex: String,
    public_key_hex: String,
    cose_key_hex: String,
    multikey: String,
}

#[derive(Clone, Copy)]
enum PqAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl PqAlgorithm {
    fn parse(name: &str) -> AuditResult<Self> {
        match name {
            "ML-DSA-44" => Ok(Self::MlDsa44),
            "ML-DSA-65" => Ok(Self::MlDsa65),
            "ML-DSA-87" => Ok(Self::MlDsa87),
            "ML-KEM-512" => Ok(Self::MlKem512),
            "ML-KEM-768" => Ok(Self::MlKem768),
            "ML-KEM-1024" => Ok(Self::MlKem1024),
            _ => Err(general(AuditReason::UnsupportedAlgorithm)),
        }
    }

    const fn cose_algorithm(self) -> i64 {
        match self {
            Self::MlDsa44 => -48,
            Self::MlDsa65 => -49,
            Self::MlDsa87 => -50,
            Self::MlKem512 => -65_537,
            Self::MlKem768 => -65_538,
            Self::MlKem1024 => -65_539,
        }
    }

    const fn multicodec(self) -> u64 {
        match self {
            Self::MlDsa44 => 0x1210,
            Self::MlDsa65 => 0x1211,
            Self::MlDsa87 => 0x1212,
            Self::MlKem512 => 0x120b,
            Self::MlKem768 => 0x120c,
            Self::MlKem1024 => 0x120d,
        }
    }

    const fn signature_len(self) -> Option<usize> {
        match self {
            Self::MlDsa44 => Some(2_420),
            Self::MlDsa65 => Some(3_309),
            Self::MlDsa87 => Some(4_627),
            Self::MlKem512 | Self::MlKem768 | Self::MlKem1024 => None,
        }
    }
}

pub(super) fn audit_suites(repo_root: &Path, ids: &mut HashSet<String>) -> AuditResult<Summary> {
    let sign1: Suite<Sign1Case> = read_json(repo_root, SIGN1_FILE, AuditContext::General)?;
    let keys: Suite<KeyCase> = read_json(repo_root, KEY_FILE, AuditContext::General)?;

    for case in &sign1.cases {
        audit_unique_id(ids, &case.id)?;
        audit_sign1(case).map_err(|error| attach_case(error, &case.id))?;
    }
    for case in &keys.cases {
        audit_unique_id(ids, &case.id)?;
        audit_key(case).map_err(|error| attach_case(error, &case.id))?;
    }

    Ok(Summary {
        sign1_cases: sign1.cases.len(),
        key_cases: keys.cases.len(),
    })
}

fn audit_sign1(case: &Sign1Case) -> AuditResult<()> {
    let algorithm = PqAlgorithm::parse(&case.algorithm)?;
    ensure(
        matches!(
            algorithm,
            PqAlgorithm::MlDsa44 | PqAlgorithm::MlDsa65 | PqAlgorithm::MlDsa87
        ),
        AuditReason::UnsupportedAlgorithm,
    )?;
    let seed = decode_hex(&case.private_key_seed_hex)?;
    let public = decode_hex(&case.public_key_hex)?;
    let expected_public = derive_public(algorithm, &seed)?;
    ensure(public == expected_public, AuditReason::SeedPublicMismatch)?;

    let kid = decode_hex(&case.kid_hex)?;
    let declared_payload = decode_hex(&case.payload_hex)?;
    let cose = decode_hex(&case.cose_sign1_hex)?;
    let root: Value = ciborium::de::from_reader(Cursor::new(&cose))
        .map_err(|_| general(AuditReason::CborDecode))?;
    let array = match root {
        Value::Array(array) if array.len() == 4 => array,
        _ => return Err(general(AuditReason::Sign1ArrayLength)),
    };
    let protected = match &array[0] {
        Value::Bytes(bytes) => bytes,
        _ => return Err(general(AuditReason::Sign1ProtectedNotBytes)),
    };
    let protected_map: Value = ciborium::de::from_reader(Cursor::new(protected))
        .map_err(|_| general(AuditReason::CborDecode))?;
    let protected_map = match protected_map {
        Value::Map(map) => map,
        _ => return Err(general(AuditReason::Sign1ProtectedNotMap)),
    };
    ensure(
        matches!(map_get(&protected_map, 1), Some(value) if super::integer_matches(value, algorithm.cose_algorithm())),
        AuditReason::ProtectedAlgorithmMismatch,
    )?;
    ensure(
        matches!(map_get(&protected_map, 4), Some(Value::Bytes(value)) if *value == kid),
        AuditReason::ProtectedKidMismatch,
    )?;
    let payload = match &array[2] {
        Value::Bytes(payload) => payload,
        _ => return Err(general(AuditReason::AttachedPayloadMissing)),
    };
    ensure(
        case.operation == "verify_attached",
        AuditReason::UnsupportedOperation,
    )?;
    ensure(
        *payload == declared_payload,
        AuditReason::AttachedPayloadMissing,
    )?;
    let signature = match &array[3] {
        Value::Bytes(signature) => signature,
        _ => return Err(general(AuditReason::Sign1SignatureShape)),
    };
    let sig_structure = encode_cbor(&Value::Array(vec![
        Value::Text("Signature1".to_owned()),
        Value::Bytes(protected.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.clone()),
    ]))?;
    let signature_valid = verify_signature(algorithm, &public, &sig_structure, signature);
    let expected_signature_len = algorithm
        .signature_len()
        .ok_or_else(|| general(AuditReason::UnsupportedAlgorithm))?;
    match case.expected_error.as_deref() {
        None => {
            ensure(
                signature.len() == expected_signature_len,
                AuditReason::SignatureWidth,
            )?;
            ensure(signature_valid, AuditReason::SignatureDidNotVerify)
        }
        Some("InvalidSignature") => {
            ensure(
                signature.len() == expected_signature_len,
                AuditReason::SignatureWidth,
            )?;
            ensure(!signature_valid, AuditReason::InvalidSignatureVerified)
        }
        Some("InvalidSignatureEncoding") => {
            ensure(
                signature.len() != expected_signature_len,
                AuditReason::InvalidSignatureEncodingWidth,
            )?;
            ensure(!signature_valid, AuditReason::InvalidSignatureVerified)
        }
        Some(_) => Err(general(AuditReason::UnsupportedExpectedError)),
    }
}

fn audit_key(case: &KeyCase) -> AuditResult<()> {
    let algorithm = PqAlgorithm::parse(&case.algorithm)?;
    let seed = decode_hex(&case.private_key_seed_hex)?;
    let public = decode_hex(&case.public_key_hex)?;
    ensure(
        derive_public(algorithm, &seed)? == public,
        AuditReason::SeedPublicMismatch,
    )?;
    let cose = decode_hex(&case.cose_key_hex)?;
    let root: Value = ciborium::de::from_reader(Cursor::new(&cose))
        .map_err(|_| general(AuditReason::CborDecode))?;
    let map = match root {
        Value::Map(map) => map,
        _ => return Err(general(AuditReason::CoseKeyRootNotMap)),
    };
    ensure(
        matches!(map_get(&map, 1), Some(value) if super::integer_matches(value, 7)),
        AuditReason::CoseKeyTypeMismatch,
    )?;
    ensure(
        matches!(map_get(&map, 3), Some(value) if super::integer_matches(value, algorithm.cose_algorithm())),
        AuditReason::CoseKeyAlgorithmMismatch,
    )?;
    ensure(
        map_get(&map, -2).is_none(),
        AuditReason::CoseKeyPrivateMaterial,
    )?;
    let encoded_public = match map_get(&map, -1) {
        Some(Value::Bytes(bytes)) => bytes,
        _ => return Err(general(AuditReason::CoseKeyMissingX)),
    };
    ensure(*encoded_public == public, AuditReason::OkpPublicMismatch)?;
    audit_multikey(&case.multikey, algorithm.multicodec(), &public)
}

fn derive_public(algorithm: PqAlgorithm, seed: &[u8]) -> AuditResult<Vec<u8>> {
    match algorithm {
        PqAlgorithm::MlDsa44 => derive_ml_dsa_public::<MlDsa44>(seed),
        PqAlgorithm::MlDsa65 => derive_ml_dsa_public::<MlDsa65>(seed),
        PqAlgorithm::MlDsa87 => derive_ml_dsa_public::<MlDsa87>(seed),
        PqAlgorithm::MlKem512 => {
            let seed = ml_kem::Seed::try_from(seed)
                .map_err(|_| general(AuditReason::InvalidSeedLength))?;
            Ok(ml_kem::ml_kem_512::DecapsulationKey::from_seed(seed)
                .encapsulation_key()
                .to_bytes()
                .to_vec())
        }
        PqAlgorithm::MlKem768 => {
            let seed = ml_kem::Seed::try_from(seed)
                .map_err(|_| general(AuditReason::InvalidSeedLength))?;
            Ok(ml_kem::ml_kem_768::DecapsulationKey::from_seed(seed)
                .encapsulation_key()
                .to_bytes()
                .to_vec())
        }
        PqAlgorithm::MlKem1024 => {
            let seed = ml_kem::Seed::try_from(seed)
                .map_err(|_| general(AuditReason::InvalidSeedLength))?;
            Ok(ml_kem::ml_kem_1024::DecapsulationKey::from_seed(seed)
                .encapsulation_key()
                .to_bytes()
                .to_vec())
        }
    }
}

fn derive_ml_dsa_public<P: MlDsaParams>(seed: &[u8]) -> AuditResult<Vec<u8>> {
    let seed = Seed::try_from(seed).map_err(|_| general(AuditReason::InvalidSeedLength))?;
    Ok(SigningKey::<P>::from_seed(&seed)
        .verifying_key()
        .to_bytes()
        .to_vec())
}

fn verify_signature(
    algorithm: PqAlgorithm,
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    match algorithm {
        PqAlgorithm::MlDsa44 => verify_ml_dsa::<MlDsa44>(public, message, signature),
        PqAlgorithm::MlDsa65 => verify_ml_dsa::<MlDsa65>(public, message, signature),
        PqAlgorithm::MlDsa87 => verify_ml_dsa::<MlDsa87>(public, message, signature),
        PqAlgorithm::MlKem512 | PqAlgorithm::MlKem768 | PqAlgorithm::MlKem1024 => false,
    }
}

fn verify_ml_dsa<P: MlDsaParams>(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(encoded_public) = EncodedVerifyingKey::<P>::try_from(public) else {
        return false;
    };
    let Ok(signature) = Signature::<P>::try_from(signature) else {
        return false;
    };
    VerifyingKey::<P>::decode(&encoded_public)
        .verify(message, &signature)
        .is_ok()
}
