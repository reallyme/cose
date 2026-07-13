// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Independent audit for committed COSE conformance vectors.
//!
//! This binary intentionally does not depend on `reallyme-cose`,
//! `reallyme-crypto`, or `reallyme-codec`. It verifies the committed JSON
//! bytes with RustCrypto, `ciborium`, and `bs58` so vector regressions are not
//! masked by bugs shared with the production implementation.

use std::collections::HashSet;
use std::fmt::{Display, Formatter, Write};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ciborium::value::Value;
use ciborium::{de::from_reader, ser::into_writer};
use serde::Deserialize;
use thiserror::Error;

const CASE_ID_BYTES: usize = 96;
const CASE_ID_BYTES_U8: u8 = 96;
const SIGN1_FILE: &str = "conformance/vectors/cose-sign1.json";
const KEY_FILE: &str = "conformance/vectors/cose-key.json";
const MANIFEST_FILE: &str = "conformance/vectors/manifest.json";

#[derive(Debug, Error)]
#[error("{context}: {reason}")]
struct AuditError {
    context: AuditContext,
    reason: AuditReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditContext {
    General,
    Manifest,
    Case(CaseId),
}

impl Display for AuditContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditContext::General => f.write_str("vector audit"),
            AuditContext::Manifest => f.write_str("manifest"),
            AuditContext::Case(case_id) => Display::fmt(case_id, f),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CaseId {
    bytes: [u8; CASE_ID_BYTES],
    len: u8,
}

impl CaseId {
    fn from_str(value: &str) -> Self {
        let mut bytes = [0_u8; CASE_ID_BYTES];
        let source = value.as_bytes();
        let copy_len = source.len().min(CASE_ID_BYTES);
        bytes[..copy_len].copy_from_slice(&source[..copy_len]);
        Self {
            bytes,
            len: u8::try_from(copy_len).unwrap_or(CASE_ID_BYTES_U8),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl Display for CaseId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for byte in self.as_bytes() {
            if byte.is_ascii_graphic() || *byte == b' ' {
                f.write_char(char::from(*byte))?;
            } else {
                f.write_str("?")?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
enum AuditReason {
    #[error("could not determine repository root")]
    CurrentDirectory,
    #[error("could not read vector file")]
    ReadFile,
    #[error("JSON decoding failed")]
    Json,
    #[error("hex decoding failed")]
    Hex,
    #[error("CBOR decoding failed")]
    CborDecode,
    #[error("CBOR encoding failed")]
    CborEncode,
    #[error("unsupported algorithm name")]
    UnsupportedAlgorithm,
    #[error("unsupported operation")]
    UnsupportedOperation,
    #[error("unsupported expected error")]
    UnsupportedExpectedError,
    #[error("seed length is invalid")]
    InvalidSeedLength,
    #[error("public key length is invalid")]
    InvalidPublicKeyLength,
    #[error("private seed does not derive the stated public key")]
    SeedPublicMismatch,
    #[error("COSE_Sign1 root is not an array")]
    Sign1RootNotArray,
    #[error("COSE_Sign1 array length is invalid")]
    Sign1ArrayLength,
    #[error("COSE_Sign1 protected header is not a byte string")]
    Sign1ProtectedNotBytes,
    #[error("COSE_Sign1 protected header is not a map")]
    Sign1ProtectedNotMap,
    #[error("COSE_Sign1 unprotected header is not a map")]
    Sign1UnprotectedNotMap,
    #[error("COSE_Sign1 payload is not byte string or null")]
    Sign1PayloadShape,
    #[error("COSE_Sign1 signature is not a byte string")]
    Sign1SignatureShape,
    #[error("attached vector does not carry an attached payload")]
    AttachedPayloadMissing,
    #[error("detached vector carries an attached payload")]
    DetachedPayloadPresent,
    #[error("happy-path vector failed independent signature verification")]
    SignatureDidNotVerify,
    #[error("negative signature vector verified independently")]
    InvalidSignatureVerified,
    #[error("signature width is not RFC 9053 fixed-width r||s")]
    SignatureWidth,
    #[error("protected algorithm label mismatch")]
    ProtectedAlgorithmMismatch,
    #[error("protected kid mismatch")]
    ProtectedKidMismatch,
    #[error("missing protected kid")]
    ProtectedKidMissing,
    #[error("key-resolution negative vector has matching resolver kid")]
    ResolverKidUnexpectedlyMatches,
    #[error("key-resolution negative vector signature is invalid")]
    ResolverNegativeSignatureInvalid,
    #[error("unsupported-algorithm vector uses a supported algorithm")]
    UnsupportedAlgorithmVectorInvalid,
    #[error("critical-header vector has no critical header")]
    CriticalHeaderMissing,
    #[error("unprotected-header vector has no integrity-sensitive unprotected label")]
    UnprotectedIntegrityFieldMissing,
    #[error("structural negative vector is not otherwise signed")]
    StructuralNegativeSignatureInvalid,
    #[error("COSE_Key root is not a map")]
    CoseKeyRootNotMap,
    #[error("COSE_Key kty mismatch")]
    CoseKeyTypeMismatch,
    #[error("COSE_Key crv mismatch")]
    CoseKeyCurveMismatch,
    #[error("COSE_Key alg mismatch")]
    CoseKeyAlgorithmMismatch,
    #[error("COSE_Key unexpected alg")]
    CoseKeyUnexpectedAlgorithm,
    #[error("COSE_Key leaks private d parameter")]
    CoseKeyPrivateMaterial,
    #[error("COSE_Key missing public x parameter")]
    CoseKeyMissingX,
    #[error("OKP public key mismatch")]
    OkpPublicMismatch,
    #[error("OKP public key width mismatch")]
    OkpPublicWidth,
    #[error("Ed25519 public key rejected by independent implementation")]
    Ed25519PublicRejected,
    #[error("EC2 y parameter missing")]
    Ec2MissingY,
    #[error("EC2 SEC1 public key mismatch")]
    Ec2PublicMismatch,
    #[error("EC2 public key rejected by independent implementation")]
    Ec2PointRejected,
    #[error("multikey is not base58btc")]
    MultikeyBase58Prefix,
    #[error("base58 decoding failed")]
    Base58,
    #[error("multicodec prefix mismatch")]
    MulticodecPrefix,
    #[error("multikey key bytes mismatch")]
    MultikeyBytes,
    #[error("manifest references an unknown suite")]
    UnknownManifestSuite,
    #[error("manifest case count mismatch")]
    ManifestCaseCount,
    #[error("duplicate vector id")]
    DuplicateCaseId,
    #[error("integer conversion failed")]
    IntegerConversion,
}

type AuditResult<T> = Result<T, AuditError>;

#[derive(Debug, Deserialize)]
struct Sign1Suite {
    cases: Vec<Sign1Case>,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
struct KeySuite {
    cases: Vec<KeyCase>,
}

#[derive(Debug, Deserialize)]
struct KeyCase {
    id: String,
    algorithm: String,
    public_key_hex: String,
    cose_key_hex: String,
    multikey: String,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    suites: Vec<ManifestSuite>,
}

#[derive(Debug, Deserialize)]
struct ManifestSuite {
    id: String,
    case_count: usize,
}

#[derive(Clone, Copy)]
enum Algorithm {
    Ed25519,
    P256,
    P384,
    P521,
    Secp256k1,
    X25519,
}

impl Algorithm {
    fn parse(name: &str) -> AuditResult<Self> {
        match name {
            "Ed25519" => Ok(Self::Ed25519),
            "P256" => Ok(Self::P256),
            "P384" => Ok(Self::P384),
            "P521" => Ok(Self::P521),
            "Secp256k1" => Ok(Self::Secp256k1),
            "X25519" => Ok(Self::X25519),
            _ => Err(general(AuditReason::UnsupportedAlgorithm)),
        }
    }

    fn cose_alg(self) -> AuditResult<i64> {
        match self {
            Self::Ed25519 => Ok(-8),
            Self::P256 => Ok(-7),
            Self::P384 => Ok(-35),
            Self::P521 => Ok(-36),
            Self::Secp256k1 => Ok(-47),
            Self::X25519 => Err(general(AuditReason::UnsupportedAlgorithm)),
        }
    }

    fn signature_width(self) -> AuditResult<usize> {
        match self {
            Self::Ed25519 | Self::P256 | Self::Secp256k1 => Ok(64),
            Self::P384 => Ok(96),
            Self::P521 => Ok(132),
            Self::X25519 => Err(general(AuditReason::UnsupportedAlgorithm)),
        }
    }
}

struct ParsedSign1 {
    protected_bytes: Vec<u8>,
    protected_map: Vec<(Value, Value)>,
    unprotected_map: Vec<(Value, Value)>,
    payload: Option<Vec<u8>>,
    signature: Vec<u8>,
}

struct CoseKeyProfile {
    kty: i64,
    crv: i64,
    alg: Option<i64>,
    multicodec: u64,
}

fn main() -> ExitCode {
    match run() {
        Ok(summary) => {
            println!(
                "vector audit passed: {} COSE_Sign1 cases, {} COSE_Key cases",
                summary.sign1_cases, summary.key_cases
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("vector audit failed: {error}");
            ExitCode::FAILURE
        }
    }
}

struct AuditSummary {
    sign1_cases: usize,
    key_cases: usize,
}

fn run() -> AuditResult<AuditSummary> {
    let repo_root = repo_root()?;
    let sign1: Sign1Suite = read_json(&repo_root, SIGN1_FILE, AuditContext::General)?;
    let keys: KeySuite = read_json(&repo_root, KEY_FILE, AuditContext::General)?;
    let manifest: Manifest = read_json(&repo_root, MANIFEST_FILE, AuditContext::Manifest)?;

    audit_manifest(&manifest, sign1.cases.len(), keys.cases.len())?;

    let mut ids = HashSet::new();
    for case in &sign1.cases {
        audit_unique_id(&mut ids, &case.id)?;
        audit_sign1(case).map_err(|error| attach_case(error, &case.id))?;
    }
    for case in &keys.cases {
        audit_unique_id(&mut ids, &case.id)?;
        audit_key(case).map_err(|error| attach_case(error, &case.id))?;
    }

    Ok(AuditSummary {
        sign1_cases: sign1.cases.len(),
        key_cases: keys.cases.len(),
    })
}

fn repo_root() -> AuditResult<PathBuf> {
    if let Some(path) = std::env::args_os().nth(1) {
        Ok(PathBuf::from(path))
    } else {
        std::env::current_dir().map_err(|_| general(AuditReason::CurrentDirectory))
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(
    repo_root: &Path,
    path: &str,
    context: AuditContext,
) -> AuditResult<T> {
    let bytes = std::fs::read(repo_root.join(path)).map_err(|_| AuditError {
        context,
        reason: AuditReason::ReadFile,
    })?;
    serde_json::from_slice(&bytes).map_err(|_| AuditError {
        context,
        reason: AuditReason::Json,
    })
}

fn audit_manifest(manifest: &Manifest, sign1_cases: usize, key_cases: usize) -> AuditResult<()> {
    for suite in &manifest.suites {
        let actual = match suite.id.as_str() {
            "cose-sign1" => sign1_cases,
            "cose-key" => key_cases,
            _ => return Err(manifest_error(AuditReason::UnknownManifestSuite)),
        };
        ensure(suite.case_count == actual, AuditReason::ManifestCaseCount).map_err(|error| {
            AuditError {
                context: AuditContext::Manifest,
                reason: error.reason,
            }
        })?;
    }
    Ok(())
}

fn audit_unique_id(ids: &mut HashSet<String>, id: &str) -> AuditResult<()> {
    if ids.insert(id.to_owned()) {
        Ok(())
    } else {
        Err(AuditError {
            context: AuditContext::Case(CaseId::from_str(id)),
            reason: AuditReason::DuplicateCaseId,
        })
    }
}

fn audit_sign1(case: &Sign1Case) -> AuditResult<()> {
    let algorithm = Algorithm::parse(&case.algorithm)?;
    let kid = decode_hex(&case.kid_hex)?;
    let public = decode_hex(&case.public_key_hex)?;
    let seed = decode_hex(&case.private_key_seed_hex)?;
    let payload = decode_hex(&case.payload_hex)?;
    let cose = decode_hex(&case.cose_sign1_hex)?;

    ensure(
        derived_public(algorithm, &seed)? == public,
        AuditReason::SeedPublicMismatch,
    )?;

    let parsed = parse_sign1(&cose)?;
    audit_payload_placement(case, &parsed)?;

    let effective_payload = parsed
        .payload
        .as_ref()
        .map_or(payload.as_slice(), Vec::as_slice);
    let signed_message = sig_structure(&parsed.protected_bytes, effective_payload)?;
    let declared_payload_message = sig_structure(&parsed.protected_bytes, &payload)?;
    let signature_ok = independent_verify(algorithm, &public, &signed_message, &parsed.signature)?;
    let declared_signature_ok = independent_verify(
        algorithm,
        &public,
        &declared_payload_message,
        &parsed.signature,
    )?;

    match case.expected_error.as_deref() {
        None => audit_happy_sign1(case, algorithm, &kid, &parsed, declared_signature_ok),
        Some("InvalidSignature") => ensure(
            !declared_signature_ok,
            AuditReason::InvalidSignatureVerified,
        ),
        Some("MissingKid") | Some("KeyNotResolved") => {
            audit_key_resolution_negative(&kid, &parsed, signature_ok)
        }
        Some("UnsupportedAlgorithm") => audit_unsupported_algorithm_negative(&parsed),
        Some("UnsupportedCriticalHeader") => ensure(
            map_get(&parsed.protected_map, 2).is_some(),
            AuditReason::CriticalHeaderMissing,
        ),
        Some("UnprotectedHeaderNotAllowed") => {
            let has_integrity_field = map_get(&parsed.unprotected_map, 1).is_some()
                || map_get(&parsed.unprotected_map, 4).is_some();
            ensure(
                has_integrity_field,
                AuditReason::UnprotectedIntegrityFieldMissing,
            )
        }
        Some("MissingPayload") | Some("InvalidFormat") => ensure(
            declared_signature_ok || signature_ok,
            AuditReason::StructuralNegativeSignatureInvalid,
        ),
        Some(_) => Err(general(AuditReason::UnsupportedExpectedError)),
    }
}

fn audit_payload_placement(case: &Sign1Case, parsed: &ParsedSign1) -> AuditResult<()> {
    match case.operation.as_str() {
        "verify_attached" => {
            if case.expected_error.as_deref() == Some("MissingPayload") {
                ensure(
                    parsed.payload.is_none(),
                    AuditReason::DetachedPayloadPresent,
                )
            } else {
                ensure(
                    parsed.payload.is_some(),
                    AuditReason::AttachedPayloadMissing,
                )
            }
        }
        "verify_detached" => {
            if case.expected_error.as_deref() == Some("InvalidFormat") {
                ensure(
                    parsed.payload.is_some(),
                    AuditReason::AttachedPayloadMissing,
                )
            } else {
                ensure(
                    parsed.payload.is_none(),
                    AuditReason::DetachedPayloadPresent,
                )
            }
        }
        _ => Err(general(AuditReason::UnsupportedOperation)),
    }
}

fn audit_happy_sign1(
    case: &Sign1Case,
    algorithm: Algorithm,
    expected_kid: &[u8],
    parsed: &ParsedSign1,
    signature_ok: bool,
) -> AuditResult<()> {
    ensure(signature_ok, AuditReason::SignatureDidNotVerify)?;
    ensure(
        parsed.signature.len() == algorithm.signature_width()?,
        AuditReason::SignatureWidth,
    )?;
    let protected_alg = map_get(&parsed.protected_map, 1)
        .ok_or_else(|| attach_case(general(AuditReason::ProtectedAlgorithmMismatch), &case.id))?;
    ensure(
        integer_matches(protected_alg, algorithm.cose_alg()?),
        AuditReason::ProtectedAlgorithmMismatch,
    )?;
    let protected_kid = map_get(&parsed.protected_map, 4)
        .ok_or_else(|| attach_case(general(AuditReason::ProtectedKidMissing), &case.id))?;
    ensure(
        matches!(protected_kid, Value::Bytes(value) if value.as_slice() == expected_kid),
        AuditReason::ProtectedKidMismatch,
    )
}

fn audit_key_resolution_negative(
    resolver_kid: &[u8],
    parsed: &ParsedSign1,
    signature_ok: bool,
) -> AuditResult<()> {
    let protected_kid = map_get(&parsed.protected_map, 4)
        .ok_or_else(|| general(AuditReason::ProtectedKidMissing))?;
    ensure(
        !matches!(protected_kid, Value::Bytes(value) if value.as_slice() == resolver_kid),
        AuditReason::ResolverKidUnexpectedlyMatches,
    )?;
    ensure(signature_ok, AuditReason::ResolverNegativeSignatureInvalid)
}

fn audit_unsupported_algorithm_negative(parsed: &ParsedSign1) -> AuditResult<()> {
    let supported = [-8_i64, -7, -35, -36, -47];
    let alg = map_get(&parsed.protected_map, 1);
    let is_supported = matches!(
        alg,
        Some(Value::Integer(integer)) if supported
            .iter()
            .any(|expected| integer_eq(*integer, *expected))
    );
    ensure(
        !is_supported,
        AuditReason::UnsupportedAlgorithmVectorInvalid,
    )
}

fn audit_key(case: &KeyCase) -> AuditResult<()> {
    let algorithm = Algorithm::parse(&case.algorithm)?;
    let public = decode_hex(&case.public_key_hex)?;
    let cose_key = decode_hex(&case.cose_key_hex)?;
    let profile = cose_key_profile(algorithm)?;
    let map = match from_reader::<Value, _>(Cursor::new(cose_key.as_slice())) {
        Ok(Value::Map(map)) => map,
        Ok(_) => return Err(general(AuditReason::CoseKeyRootNotMap)),
        Err(_) => return Err(general(AuditReason::CborDecode)),
    };

    ensure(
        matches!(map_get(&map, 1), Some(value) if integer_matches(value, profile.kty)),
        AuditReason::CoseKeyTypeMismatch,
    )?;
    ensure(
        matches!(map_get(&map, -1), Some(value) if integer_matches(value, profile.crv)),
        AuditReason::CoseKeyCurveMismatch,
    )?;
    match profile.alg {
        Some(expected_alg) => ensure(
            matches!(map_get(&map, 3), Some(value) if integer_matches(value, expected_alg)),
            AuditReason::CoseKeyAlgorithmMismatch,
        )?,
        None => ensure(
            map_get(&map, 3).is_none(),
            AuditReason::CoseKeyUnexpectedAlgorithm,
        )?,
    }
    ensure(
        map_get(&map, -4).is_none(),
        AuditReason::CoseKeyPrivateMaterial,
    )?;

    let x = match map_get(&map, -2) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        _ => return Err(general(AuditReason::CoseKeyMissingX)),
    };

    match profile.kty {
        1 => audit_okp_key(algorithm, x, &public)?,
        2 => audit_ec2_key(algorithm, x, &public, &map)?,
        _ => return Err(general(AuditReason::CoseKeyTypeMismatch)),
    }
    audit_multikey(&case.multikey, profile.multicodec, &public)
}

fn audit_okp_key(algorithm: Algorithm, x: &[u8], public: &[u8]) -> AuditResult<()> {
    ensure(x == public, AuditReason::OkpPublicMismatch)?;
    ensure(x.len() == 32, AuditReason::OkpPublicWidth)?;
    if matches!(algorithm, Algorithm::Ed25519) {
        use ed25519_dalek::VerifyingKey;
        let bytes = fixed_32(x, AuditReason::InvalidPublicKeyLength)?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|_| general(AuditReason::Ed25519PublicRejected))?;
    }
    Ok(())
}

fn audit_ec2_key(
    algorithm: Algorithm,
    x: &[u8],
    public: &[u8],
    map: &[(Value, Value)],
) -> AuditResult<()> {
    let sec1 = match map_get(map, -3) {
        Some(Value::Bool(y_sign)) => {
            let mut out = Vec::with_capacity(
                x.len()
                    .checked_add(1)
                    .ok_or_else(|| general(AuditReason::IntegerConversion))?,
            );
            out.push(if *y_sign { 0x03 } else { 0x02 });
            out.extend_from_slice(x);
            out
        }
        Some(Value::Bytes(y)) => {
            let capacity = x
                .len()
                .checked_add(y.len())
                .ok_or_else(|| general(AuditReason::IntegerConversion))?;
            let mut out = Vec::with_capacity(capacity);
            out.extend_from_slice(x);
            out.extend_from_slice(y);
            out
        }
        _ => return Err(general(AuditReason::Ec2MissingY)),
    };
    ensure(sec1 == public, AuditReason::Ec2PublicMismatch)?;
    ensure(
        ec2_point_is_valid(algorithm, &sec1),
        AuditReason::Ec2PointRejected,
    )
}

fn audit_multikey(multikey: &str, codec: u64, public: &[u8]) -> AuditResult<()> {
    ensure(multikey.starts_with('z'), AuditReason::MultikeyBase58Prefix)?;
    let decoded = bs58::decode(&multikey[1..])
        .into_vec()
        .map_err(|_| general(AuditReason::Base58))?;
    let prefix = multicodec_varint(codec)?;
    ensure(decoded.starts_with(&prefix), AuditReason::MulticodecPrefix)?;
    ensure(
        decoded[prefix.len()..] == *public,
        AuditReason::MultikeyBytes,
    )
}

fn parse_sign1(bytes: &[u8]) -> AuditResult<ParsedSign1> {
    let root: Value =
        from_reader(Cursor::new(bytes)).map_err(|_| general(AuditReason::CborDecode))?;
    let array = match root {
        Value::Array(array) => array,
        Value::Tag(18, inner) => match *inner {
            Value::Array(array) => array,
            _ => return Err(general(AuditReason::Sign1RootNotArray)),
        },
        _ => return Err(general(AuditReason::Sign1RootNotArray)),
    };
    ensure(array.len() == 4, AuditReason::Sign1ArrayLength)?;

    let protected_bytes = match &array[0] {
        Value::Bytes(bytes) => bytes.clone(),
        _ => return Err(general(AuditReason::Sign1ProtectedNotBytes)),
    };
    let protected_map = match from_reader::<Value, _>(Cursor::new(protected_bytes.as_slice())) {
        Ok(Value::Map(map)) => map,
        Ok(_) => return Err(general(AuditReason::Sign1ProtectedNotMap)),
        Err(_) => return Err(general(AuditReason::CborDecode)),
    };
    let unprotected_map = match &array[1] {
        Value::Map(map) => map.clone(),
        _ => return Err(general(AuditReason::Sign1UnprotectedNotMap)),
    };
    let payload = match &array[2] {
        Value::Bytes(bytes) => Some(bytes.clone()),
        Value::Null => None,
        _ => return Err(general(AuditReason::Sign1PayloadShape)),
    };
    let signature = match &array[3] {
        Value::Bytes(bytes) => bytes.clone(),
        _ => return Err(general(AuditReason::Sign1SignatureShape)),
    };

    Ok(ParsedSign1 {
        protected_bytes,
        protected_map,
        unprotected_map,
        payload,
        signature,
    })
}

fn derived_public(algorithm: Algorithm, seed: &[u8]) -> AuditResult<Vec<u8>> {
    match algorithm {
        Algorithm::Ed25519 => {
            use ed25519_dalek::SigningKey;
            let seed_bytes = fixed_32(seed, AuditReason::InvalidSeedLength)?;
            let signing_key = SigningKey::from_bytes(&seed_bytes);
            Ok(signing_key.verifying_key().to_bytes().to_vec())
        }
        Algorithm::P256 => {
            use p256::ecdsa::SigningKey;
            let signing_key = SigningKey::from_slice(seed)
                .map_err(|_| general(AuditReason::InvalidSeedLength))?;
            Ok(signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec())
        }
        Algorithm::P384 => {
            use p384::ecdsa::SigningKey;
            let signing_key = SigningKey::from_slice(seed)
                .map_err(|_| general(AuditReason::InvalidSeedLength))?;
            Ok(signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec())
        }
        Algorithm::P521 => {
            use p521::elliptic_curve::sec1::ToEncodedPoint;
            let secret_key = p521::SecretKey::from_slice(seed)
                .map_err(|_| general(AuditReason::InvalidSeedLength))?;
            Ok(secret_key
                .public_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec())
        }
        Algorithm::Secp256k1 => {
            use k256::ecdsa::SigningKey;
            let signing_key = SigningKey::from_slice(seed)
                .map_err(|_| general(AuditReason::InvalidSeedLength))?;
            Ok(signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec())
        }
        Algorithm::X25519 => Err(general(AuditReason::UnsupportedAlgorithm)),
    }
}

fn independent_verify(
    algorithm: Algorithm,
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> AuditResult<bool> {
    match algorithm {
        Algorithm::Ed25519 => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let public_key =
                VerifyingKey::from_bytes(&fixed_32(public, AuditReason::InvalidPublicKeyLength)?)
                    .map_err(|_| general(AuditReason::InvalidPublicKeyLength))?;
            let Ok(sig) = Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(public_key.verify(message, &sig).is_ok())
        }
        Algorithm::P256 => {
            use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let Ok(public_key) = VerifyingKey::from_sec1_bytes(public) else {
                return Ok(false);
            };
            let Ok(sig) = Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(public_key.verify(message, &sig).is_ok())
        }
        Algorithm::P384 => {
            use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let Ok(public_key) = VerifyingKey::from_sec1_bytes(public) else {
                return Ok(false);
            };
            let Ok(sig) = Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(public_key.verify(message, &sig).is_ok())
        }
        Algorithm::P521 => {
            use p521::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let Ok(public_key) = VerifyingKey::from_sec1_bytes(public) else {
                return Ok(false);
            };
            let Ok(sig) = Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(public_key.verify(message, &sig).is_ok())
        }
        Algorithm::Secp256k1 => {
            use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let Ok(public_key) = VerifyingKey::from_sec1_bytes(public) else {
                return Ok(false);
            };
            let Ok(sig) = Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(public_key.verify(message, &sig).is_ok())
        }
        Algorithm::X25519 => Err(general(AuditReason::UnsupportedAlgorithm)),
    }
}

fn ec2_point_is_valid(algorithm: Algorithm, sec1: &[u8]) -> bool {
    match algorithm {
        Algorithm::P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1).is_ok(),
        Algorithm::P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(sec1).is_ok(),
        Algorithm::P521 => p521::ecdsa::VerifyingKey::from_sec1_bytes(sec1).is_ok(),
        Algorithm::Secp256k1 => k256::ecdsa::VerifyingKey::from_sec1_bytes(sec1).is_ok(),
        Algorithm::Ed25519 | Algorithm::X25519 => false,
    }
}

fn cose_key_profile(algorithm: Algorithm) -> AuditResult<CoseKeyProfile> {
    match algorithm {
        Algorithm::Ed25519 => Ok(CoseKeyProfile {
            kty: 1,
            crv: 6,
            alg: Some(-8),
            multicodec: 0xed,
        }),
        Algorithm::X25519 => Ok(CoseKeyProfile {
            kty: 1,
            crv: 4,
            alg: None,
            multicodec: 0xec,
        }),
        Algorithm::P256 => Ok(CoseKeyProfile {
            kty: 2,
            crv: 1,
            alg: Some(-7),
            multicodec: 0x1200,
        }),
        Algorithm::P384 => Ok(CoseKeyProfile {
            kty: 2,
            crv: 2,
            alg: Some(-35),
            multicodec: 0x1201,
        }),
        Algorithm::P521 => Ok(CoseKeyProfile {
            kty: 2,
            crv: 3,
            alg: Some(-36),
            multicodec: 0x1202,
        }),
        Algorithm::Secp256k1 => Ok(CoseKeyProfile {
            kty: 2,
            crv: 8,
            alg: Some(-47),
            multicodec: 0xe7,
        }),
    }
}

fn sig_structure(protected: &[u8], payload: &[u8]) -> AuditResult<Vec<u8>> {
    encode_cbor(&Value::Array(vec![
        Value::Text("Signature1".to_owned()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
}

fn encode_cbor(value: &Value) -> AuditResult<Vec<u8>> {
    let mut out = Vec::new();
    into_writer(value, Cursor::new(&mut out)).map_err(|_| general(AuditReason::CborEncode))?;
    Ok(out)
}

fn map_get(map: &[(Value, Value)], label: i64) -> Option<&Value> {
    map.iter()
        .find(|(key, _)| matches!(key, Value::Integer(integer) if integer_eq(*integer, label)))
        .map(|(_, value)| value)
}

fn integer_matches(value: &Value, expected: i64) -> bool {
    matches!(value, Value::Integer(integer) if integer_eq(*integer, expected))
}

fn integer_eq(integer: ciborium::value::Integer, expected: i64) -> bool {
    i128::from(integer) == i128::from(expected)
}

fn decode_hex(input: &str) -> AuditResult<Vec<u8>> {
    hex::decode(input).map_err(|_| general(AuditReason::Hex))
}

fn fixed_32(bytes: &[u8], reason: AuditReason) -> AuditResult<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).map_err(|_| general(reason))
}

fn multicodec_varint(code: u64) -> AuditResult<Vec<u8>> {
    let mut value = code;
    let mut out = Vec::new();
    loop {
        let low = value & 0x7f;
        let mut byte = u8::try_from(low).map_err(|_| general(AuditReason::IntegerConversion))?;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return Ok(out);
        }
    }
}

fn ensure(condition: bool, reason: AuditReason) -> AuditResult<()> {
    if condition {
        Ok(())
    } else {
        Err(general(reason))
    }
}

fn general(reason: AuditReason) -> AuditError {
    AuditError {
        context: AuditContext::General,
        reason,
    }
}

fn manifest_error(reason: AuditReason) -> AuditError {
    AuditError {
        context: AuditContext::Manifest,
        reason,
    }
}

fn attach_case(error: AuditError, id: &str) -> AuditError {
    AuditError {
        context: match error.context {
            AuditContext::Manifest => AuditContext::Manifest,
            AuditContext::General | AuditContext::Case(_) => {
                AuditContext::Case(CaseId::from_str(id))
            }
        },
        reason: error.reason,
    }
}
