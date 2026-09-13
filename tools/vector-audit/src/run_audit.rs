// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn main() -> ExitCode {
    match run() {
        Ok(summary) => {
            println!(
                "vector audit passed: {} classical COSE_Sign1 cases, {} PQ COSE_Sign1 cases, {} classical COSE_Key cases, {} PQ COSE_Key cases, {} ML-KEM COSE_Encrypt cases",
                summary.sign1_cases,
                summary.pq_sign1_cases,
                summary.key_cases,
                summary.pq_key_cases,
                summary.ml_kem_encrypt_cases
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
    pq_sign1_cases: usize,
    pq_key_cases: usize,
    ml_kem_encrypt_cases: usize,
}

fn run() -> AuditResult<AuditSummary> {
    let repo_root = repo_root()?;
    let sign1: Sign1Suite = read_json(&repo_root, SIGN1_FILE, AuditContext::General)?;
    let keys: KeySuite = read_json(&repo_root, KEY_FILE, AuditContext::General)?;
    let ml_kem_encrypt: ml_kem_encrypt::Suite =
        read_json(&repo_root, ML_KEM_ENCRYPT_FILE, AuditContext::General)?;
    let manifest: verify_manifest::Manifest =
        read_json(&repo_root, MANIFEST_FILE, AuditContext::Manifest)?;

    let mut ids = HashSet::new();
    let pq_summary = pq::audit_suites(&repo_root, &mut ids)?;

    verify_manifest::verify(
        &repo_root,
        &manifest,
        sign1.cases.len(),
        keys.cases.len(),
        pq_summary.sign1_cases,
        pq_summary.key_cases,
        ml_kem_encrypt.cases.len(),
    )?;

    ensure(
        sign1.cases.iter().any(|case| {
            case.provenance == Some(Provenance::NodeOpenSslRfc8032) && case.expected_error.is_none()
        }),
        AuditReason::ExternalSign1VectorMissing,
    )?;

    for case in &sign1.cases {
        audit_unique_id(&mut ids, &case.id)?;
        audit_sign1(case).map_err(|error| attach_case(error, &case.id))?;
    }
    for case in &keys.cases {
        audit_unique_id(&mut ids, &case.id)?;
        audit_key(case).map_err(|error| attach_case(error, &case.id))?;
    }
    ml_kem_encrypt::audit_suite(&ml_kem_encrypt, &mut ids)?;

    Ok(AuditSummary {
        sign1_cases: sign1.cases.len(),
        key_cases: keys.cases.len(),
        pq_sign1_cases: pq_summary.sign1_cases,
        pq_key_cases: pq_summary.key_cases,
        ml_kem_encrypt_cases: ml_kem_encrypt.cases.len(),
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
        Some("InvalidSignature" | "InvalidSignatureEncoding") => ensure(
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
    let supported = [-19_i64, -7, -9, -51, -52, -47, -48, -49, -50];
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
