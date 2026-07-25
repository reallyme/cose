// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Verify that the manifest binds every vector suite by path, count, and digest.

use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{ensure, manifest_error, AuditContext, AuditError, AuditReason, AuditResult};

const EXPECTED_SUITE_COUNT: usize = 5;

#[derive(Debug, Deserialize)]
pub(super) struct Manifest {
    suites: Vec<ManifestSuite>,
}

#[derive(Debug, Deserialize)]
struct ManifestSuite {
    id: String,
    path: String,
    case_count: usize,
    sha256: String,
}

struct ExpectedSuite<'a> {
    id: &'static str,
    path: &'static str,
    case_count: usize,
    repo_root: &'a Path,
}

pub(super) fn verify(
    repo_root: &Path,
    manifest: &Manifest,
    sign1_cases: usize,
    key_cases: usize,
    pq_sign1_cases: usize,
    pq_key_cases: usize,
    ml_kem_encrypt_cases: usize,
) -> AuditResult<()> {
    let expected = [
        ExpectedSuite {
            id: "cose-sign1",
            path: "cose-sign1.json",
            case_count: sign1_cases,
            repo_root,
        },
        ExpectedSuite {
            id: "cose-key",
            path: "cose-key.json",
            case_count: key_cases,
            repo_root,
        },
        ExpectedSuite {
            id: "cose-sign1-pq",
            path: "cose-sign1-pq.json",
            case_count: pq_sign1_cases,
            repo_root,
        },
        ExpectedSuite {
            id: "cose-key-pq",
            path: "cose-key-pq.json",
            case_count: pq_key_cases,
            repo_root,
        },
        ExpectedSuite {
            id: "cose-encrypt-ml-kem",
            path: "cose-encrypt-ml-kem.json",
            case_count: ml_kem_encrypt_cases,
            repo_root,
        },
    ];

    ensure(
        manifest.suites.len() == EXPECTED_SUITE_COUNT,
        AuditReason::ManifestSuiteSet,
    )
    .map_err(manifest_context)?;
    for expected_suite in expected {
        let mut matches = manifest
            .suites
            .iter()
            .filter(|suite| suite.id == expected_suite.id);
        let suite = matches
            .next()
            .ok_or_else(|| manifest_error(AuditReason::ManifestSuiteSet))?;
        ensure(matches.next().is_none(), AuditReason::ManifestSuiteSet)
            .map_err(manifest_context)?;
        ensure(suite.path == expected_suite.path, AuditReason::ManifestPath)
            .map_err(manifest_context)?;
        ensure(
            suite.case_count == expected_suite.case_count,
            AuditReason::ManifestCaseCount,
        )
        .map_err(manifest_context)?;
        verify_digest(&expected_suite, suite)?;
    }
    Ok(())
}

fn verify_digest(expected: &ExpectedSuite<'_>, suite: &ManifestSuite) -> AuditResult<()> {
    let mut manifest_digest = [0_u8; 32];
    hex::decode_to_slice(&suite.sha256, &mut manifest_digest)
        .map_err(|_| manifest_error(AuditReason::ManifestDigestEncoding))?;
    let bytes = std::fs::read(expected.repo_root.join("vectors").join(expected.path))
        .map_err(|_| manifest_error(AuditReason::ReadFile))?;
    let actual_digest = Sha256::digest(bytes);
    ensure(
        actual_digest.as_slice() == manifest_digest,
        AuditReason::ManifestDigest,
    )
    .map_err(manifest_context)
}

fn manifest_context(error: AuditError) -> AuditError {
    AuditError {
        context: AuditContext::Manifest,
        reason: error.reason,
    }
}
