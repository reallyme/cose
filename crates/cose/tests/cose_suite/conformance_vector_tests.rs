#![allow(missing_docs, clippy::expect_used, clippy::panic, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::{
    cose_decrypt_ml_kem_with_external_aad, cose_key_from_public_bytes, cose_key_from_slice,
    cose_key_to_multikey, cose_key_to_public_bytes, cose_key_to_vec, cose_verify1,
    cose_verify1_detached, derive_kid_from_cose_key_public, multikey_to_cose_key, Algorithm,
    CoseContentEncryptionAlgorithm, CoseError, CoseMlKemAlgorithm, CoseMlKemDecryptRequest,
    CoseMlKemMode,
};
use serde::Deserialize;

const COSE_SIGN1_VECTORS: &str = include_str!("../../../../vectors/cose-sign1.json");
const COSE_KEY_VECTORS: &str = include_str!("../../../../vectors/cose-key.json");
const COSE_PQ_SIGN1_VECTORS: &str = include_str!("../../../../vectors/cose-sign1-pq.json");
const COSE_PQ_KEY_VECTORS: &str = include_str!("../../../../vectors/cose-key-pq.json");
const COSE_ML_KEM_ENCRYPT_VECTORS: &str =
    include_str!("../../../../vectors/cose-encrypt-ml-kem.json");
const VECTOR_MANIFEST: &str = include_str!("../../../../vectors/manifest.json");

#[derive(Debug, Deserialize)]
struct Manifest {
    suites: Vec<ManifestSuite>,
}

#[derive(Debug, Deserialize)]
struct ManifestSuite {
    id: String,
    case_count: usize,
}

#[test]
fn manifest_case_counts_match_suites() {
    let manifest: Manifest = serde_json::from_str(VECTOR_MANIFEST).expect("manifest must parse");
    let sign1: CoseSign1Suite =
        serde_json::from_str(COSE_SIGN1_VECTORS).expect("COSE_Sign1 vectors must parse");
    let key: CoseKeySuite =
        serde_json::from_str(COSE_KEY_VECTORS).expect("COSE_Key vectors must parse");
    let pq_sign1: CoseSign1Suite =
        serde_json::from_str(COSE_PQ_SIGN1_VECTORS).expect("PQ COSE_Sign1 vectors must parse");
    let pq_key: CoseKeySuite =
        serde_json::from_str(COSE_PQ_KEY_VECTORS).expect("PQ COSE_Key vectors must parse");
    let encrypt: CoseMlKemEncryptSuite = serde_json::from_str(COSE_ML_KEM_ENCRYPT_VECTORS)
        .expect("ML-KEM COSE_Encrypt vectors must parse");

    for suite in manifest.suites {
        let actual = match suite.id.as_str() {
            "cose-sign1" => sign1.cases.len(),
            "cose-key" => key.cases.len(),
            "cose-sign1-pq" => pq_sign1.cases.len(),
            "cose-key-pq" => pq_key.cases.len(),
            "cose-encrypt-ml-kem" => encrypt.cases.len(),
            other => panic!("unknown manifest suite: {other}"),
        };
        assert_eq!(suite.case_count, actual, "case count for {}", suite.id);
    }
}

#[derive(Debug, Deserialize)]
struct CoseSign1Suite {
    cases: Vec<CoseSign1Case>,
}

#[derive(Debug, Deserialize)]
struct CoseSign1Case {
    id: String,
    operation: String,
    algorithm: String,
    kid_hex: String,
    public_key_hex: String,
    payload_hex: String,
    cose_sign1_hex: String,
    expected_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CoseKeySuite {
    cases: Vec<CoseKeyCase>,
}

#[derive(Debug, Deserialize)]
struct CoseKeyCase {
    id: String,
    algorithm: String,
    public_key_hex: String,
    cose_key_hex: String,
    multikey: String,
}

#[derive(Debug, Deserialize)]
struct CoseMlKemEncryptSuite {
    cases: Vec<CoseMlKemEncryptCase>,
}

#[derive(Debug, Deserialize)]
struct CoseMlKemEncryptCase {
    id: String,
    kem_algorithm: String,
    mode: String,
    content_algorithm: String,
    private_key_seed_hex: String,
    public_key_hex: String,
    recipient_kid_hex: String,
    plaintext_hex: String,
    external_aad_hex: String,
    supp_priv_info_hex: String,
    cose_encrypt_hex: String,
}

#[test]
fn portable_cose_sign1_vectors_verify() {
    let suite: CoseSign1Suite =
        serde_json::from_str(COSE_SIGN1_VECTORS).expect("COSE_Sign1 vectors must parse");

    for case in suite.cases {
        let kid = decode_hex(&case.kid_hex);
        let public_key = decode_hex(&case.public_key_hex);
        let payload = decode_hex(&case.payload_hex);
        let cose = decode_hex(&case.cose_sign1_hex);

        let result = match case.operation.as_str() {
            "verify_attached" => cose_verify1(&cose, |_, requested_kid| {
                resolve_expected_kid(requested_kid, &kid, &public_key)
            })
            .map(|verified_payload| {
                assert_eq!(
                    verified_payload.as_slice(),
                    payload.as_slice(),
                    "{}",
                    case.id
                );
            }),
            "verify_detached" => cose_verify1_detached(&cose, &payload, |_, requested_kid| {
                resolve_expected_kid(requested_kid, &kid, &public_key)
            }),
            _ => panic!("unknown vector operation: {}", case.operation),
        };

        // The algorithm field is asserted to be a supported name; the
        // algorithm actually used comes from the message's protected header.
        let _ = algorithm_from_name(&case.algorithm);
        assert_vector_result(&case.id, result, case.expected_error.as_deref());
    }
}

#[test]
fn portable_pq_cose_sign1_vectors_verify() {
    let suite: CoseSign1Suite =
        serde_json::from_str(COSE_PQ_SIGN1_VECTORS).expect("PQ COSE_Sign1 vectors must parse");
    verify_sign1_suite(suite);
}

fn verify_sign1_suite(suite: CoseSign1Suite) {
    for case in suite.cases {
        let kid = decode_hex(&case.kid_hex);
        let public_key = decode_hex(&case.public_key_hex);
        let payload = decode_hex(&case.payload_hex);
        let cose = decode_hex(&case.cose_sign1_hex);

        let result = match case.operation.as_str() {
            "verify_attached" => cose_verify1(&cose, |_, requested_kid| {
                resolve_expected_kid(requested_kid, &kid, &public_key)
            })
            .map(|verified_payload| {
                assert_eq!(
                    verified_payload.as_slice(),
                    payload.as_slice(),
                    "{}",
                    case.id
                );
            }),
            "verify_detached" => cose_verify1_detached(&cose, &payload, |_, requested_kid| {
                resolve_expected_kid(requested_kid, &kid, &public_key)
            }),
            _ => panic!("unknown vector operation: {}", case.operation),
        };

        let _ = algorithm_from_name(&case.algorithm);
        assert_vector_result(&case.id, result, case.expected_error.as_deref());
    }
}

#[test]
fn portable_cose_key_vectors_roundtrip() {
    let suite: CoseKeySuite =
        serde_json::from_str(COSE_KEY_VECTORS).expect("COSE_Key vectors must parse");

    for case in suite.cases {
        let algorithm = algorithm_from_name(&case.algorithm);
        let public_key = decode_hex(&case.public_key_hex);
        let cose_key_bytes = decode_hex(&case.cose_key_hex);

        let decoded_key = cose_key_from_slice(&cose_key_bytes).expect("COSE_Key must decode");
        assert_eq!(
            cose_key_to_public_bytes(&decoded_key).expect("public key must extract"),
            public_key,
            "{}",
            case.id
        );
        assert_eq!(
            cose_key_to_vec(&decoded_key)
                .expect("COSE_Key must re-encode")
                .as_slice(),
            cose_key_bytes.as_slice(),
            "{}",
            case.id
        );
        assert_eq!(
            cose_key_to_multikey(&decoded_key)
                .expect("multikey must encode")
                .as_str(),
            case.multikey.as_str(),
            "{}",
            case.id
        );

        let rebuilt_key =
            cose_key_from_public_bytes(algorithm, &public_key).expect("COSE_Key must rebuild");
        assert_eq!(
            cose_key_to_vec(&rebuilt_key)
                .expect("rebuilt COSE_Key must encode")
                .as_slice(),
            cose_key_bytes.as_slice(),
            "{}",
            case.id
        );
    }
}

#[test]
fn portable_pq_cose_key_and_multikey_vectors_roundtrip() {
    let suite: CoseKeySuite =
        serde_json::from_str(COSE_PQ_KEY_VECTORS).expect("PQ COSE_Key vectors must parse");

    for case in suite.cases {
        let algorithm = algorithm_from_name(&case.algorithm);
        let public_key = decode_hex(&case.public_key_hex);
        let cose_key_bytes = decode_hex(&case.cose_key_hex);
        let decoded_key = cose_key_from_slice(&cose_key_bytes).expect("PQ COSE_Key must decode");

        assert_eq!(
            cose_key_to_public_bytes(&decoded_key).expect("PQ public key must extract"),
            public_key,
            "{}",
            case.id
        );
        assert_eq!(
            cose_key_to_multikey(&decoded_key)
                .expect("PQ multikey must encode")
                .as_str(),
            case.multikey.as_str(),
            "{}",
            case.id
        );
        let from_multikey =
            multikey_to_cose_key(&case.multikey).expect("PQ Multikey must convert to COSE_Key");
        assert_eq!(
            cose_key_to_vec(&from_multikey)
                .expect("PQ Multikey-derived COSE_Key must encode")
                .as_slice(),
            cose_key_bytes.as_slice(),
            "{}",
            case.id
        );
        let rebuilt =
            cose_key_from_public_bytes(algorithm, &public_key).expect("PQ COSE_Key must rebuild");
        assert_eq!(
            cose_key_to_vec(&rebuilt)
                .expect("PQ COSE_Key must encode")
                .as_slice(),
            cose_key_bytes.as_slice(),
            "{}",
            case.id
        );
    }
}

#[test]
fn portable_cose_key_vectors_roundtrip_reallyme_codec() {
    // Exercise the multikey strings directly at the reallyme-codec layer,
    // independent of this crate's COSE_Key conversion functions.
    use reallyme_codec::multikey::{encode_multikey, parse_multikey};

    let suite: CoseKeySuite =
        serde_json::from_str(COSE_KEY_VECTORS).expect("COSE_Key vectors must parse");

    for case in suite.cases {
        let public_key = decode_hex(&case.public_key_hex);
        let codec_name = multikey_codec_name(&case.algorithm);

        assert_eq!(
            encode_multikey(codec_name, &public_key).expect("codec multikey must encode"),
            case.multikey,
            "{}",
            case.id
        );

        let parsed = parse_multikey(&case.multikey).expect("codec multikey must parse");
        assert_eq!(parsed.codec_name, codec_name, "{}", case.id);
        assert_eq!(parsed.public_key, public_key, "{}", case.id);
    }
}

#[test]
fn deterministic_ml_kem_cose_encrypt_vectors_decrypt_and_preserve_metadata() {
    let suite: CoseMlKemEncryptSuite = serde_json::from_str(COSE_ML_KEM_ENCRYPT_VECTORS)
        .expect("ML-KEM COSE_Encrypt vectors must parse");

    for case in suite.cases {
        let (crypto_algorithm, kem_algorithm) = ml_kem_algorithm_from_name(&case.kem_algorithm);
        let content_algorithm = content_algorithm_from_name(&case.content_algorithm);
        let mode = ml_kem_mode_from_name(&case.mode);
        let private_key = decode_hex(&case.private_key_seed_hex);
        let public_key = decode_hex(&case.public_key_hex);
        let kid = decode_hex(&case.recipient_kid_hex);
        let plaintext = decode_hex(&case.plaintext_hex);
        let external_aad = decode_hex(&case.external_aad_hex);
        let supp_priv_info = decode_hex(&case.supp_priv_info_hex);
        let cose_encrypt = decode_hex(&case.cose_encrypt_hex);

        let public_cose_key = cose_key_from_public_bytes(crypto_algorithm, &public_key)
            .expect("vector public key must form a COSE_Key");
        assert_eq!(
            derive_kid_from_cose_key_public(&public_cose_key)
                .expect("vector public COSE_Key must derive a kid")
                .as_slice(),
            kid.as_slice(),
            "{}",
            case.id
        );

        let decrypted = cose_decrypt_ml_kem_with_external_aad(
            &CoseMlKemDecryptRequest::new(&cose_encrypt, &private_key, &kid, Some(&supp_priv_info)),
            &external_aad,
        )
        .expect("committed ML-KEM COSE_Encrypt vector must decrypt");

        assert_eq!(decrypted.plaintext.as_slice(), plaintext, "{}", case.id);
        assert_eq!(decrypted.kem_algorithm, kem_algorithm, "{}", case.id);
        assert_eq!(
            decrypted.content_algorithm, content_algorithm,
            "{}",
            case.id
        );
        assert_eq!(decrypted.mode, mode, "{}", case.id);
        assert_eq!(decrypted.kid.as_slice(), kid, "{}", case.id);
    }
}

fn multikey_codec_name(algorithm: &str) -> &'static str {
    match algorithm {
        "Ed25519" => "ed25519-pub",
        "X25519" => "x25519-pub",
        "P256" => "p256-pub",
        "P384" => "p384-pub",
        "P521" => "p521-pub",
        "Secp256k1" => "secp256k1-pub",
        other => panic!("unsupported algorithm name: {other}"),
    }
}

fn ml_kem_algorithm_from_name(name: &str) -> (Algorithm, CoseMlKemAlgorithm) {
    match name {
        "ML-KEM-512" => (Algorithm::MlKem512, CoseMlKemAlgorithm::MlKem512),
        "ML-KEM-768" => (Algorithm::MlKem768, CoseMlKemAlgorithm::MlKem768),
        "ML-KEM-1024" => (Algorithm::MlKem1024, CoseMlKemAlgorithm::MlKem1024),
        other => panic!("unsupported ML-KEM algorithm name: {other}"),
    }
}

fn content_algorithm_from_name(name: &str) -> CoseContentEncryptionAlgorithm {
    match name {
        "A128GCM" => CoseContentEncryptionAlgorithm::Aes128Gcm,
        "A192GCM" => CoseContentEncryptionAlgorithm::Aes192Gcm,
        "A256GCM" => CoseContentEncryptionAlgorithm::Aes256Gcm,
        other => panic!("unsupported content algorithm name: {other}"),
    }
}

fn ml_kem_mode_from_name(name: &str) -> CoseMlKemMode {
    match name {
        "direct" => CoseMlKemMode::Direct,
        "key_wrap" => CoseMlKemMode::KeyWrap,
        other => panic!("unsupported ML-KEM mode name: {other}"),
    }
}

fn resolve_expected_kid(
    requested_kid: &[u8],
    expected_kid: &[u8],
    public_key: &[u8],
) -> Option<Vec<u8>> {
    if requested_kid == expected_kid {
        Some(public_key.to_vec())
    } else {
        None
    }
}

fn assert_vector_result(id: &str, result: Result<(), CoseError>, expected_error: Option<&str>) {
    match expected_error {
        Some(name) => {
            assert_eq!(
                result.expect_err(id),
                cose_error_from_name(id, name),
                "{id}"
            );
        }
        None => result.expect(id),
    }
}

fn cose_error_from_name(id: &str, name: &str) -> CoseError {
    match name {
        "InvalidSignature" => CoseError::InvalidSignature,
        "InvalidSignatureEncoding" => CoseError::InvalidSignatureEncoding,
        "MissingKid" => CoseError::MissingKid,
        "KeyNotResolved" => CoseError::KeyNotResolved,
        "MissingPayload" => CoseError::MissingPayload,
        "InvalidFormat" => CoseError::InvalidFormat,
        "UnsupportedAlgorithm" => CoseError::UnsupportedAlgorithm,
        "UnsupportedCriticalHeader" => CoseError::UnsupportedCriticalHeader,
        "UnprotectedHeaderNotAllowed" => CoseError::UnprotectedHeaderNotAllowed,
        "ResourceLimitExceeded" => CoseError::ResourceLimitExceeded,
        "NonCanonicalCbor" => CoseError::NonCanonicalCbor,
        "UnexpectedCborTag" => CoseError::UnexpectedCborTag,
        "Cbor" => CoseError::Cbor,
        other => panic!("unsupported expected error in vector {id}: {other}"),
    }
}

fn algorithm_from_name(name: &str) -> Algorithm {
    match name {
        "Ed25519" => Algorithm::Ed25519,
        "P256" => Algorithm::P256,
        "P384" => Algorithm::P384,
        "P521" => Algorithm::P521,
        "Secp256k1" => Algorithm::Secp256k1,
        "X25519" => Algorithm::X25519,
        "ML-DSA-44" => Algorithm::MlDsa44,
        "ML-DSA-65" => Algorithm::MlDsa65,
        "ML-DSA-87" => Algorithm::MlDsa87,
        "ML-KEM-512" => Algorithm::MlKem512,
        "ML-KEM-768" => Algorithm::MlKem768,
        "ML-KEM-1024" => Algorithm::MlKem1024,
        _ => panic!("unsupported algorithm name: {name}"),
    }
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input must have an even length");

    input
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let high = decode_hex_nibble(chunk[0]);
            let low = decode_hex_nibble(chunk[1]);
            (high << 4) | low
        })
        .collect()
}

fn decode_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex character"),
    }
}
