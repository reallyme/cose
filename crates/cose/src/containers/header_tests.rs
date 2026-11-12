// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{
    assert_error, envelope, fixtures, hex, int, key, map, policy, request, suite, Trust,
};
use crate::containers::{
    verify_container, ContainerError, ContainerErrorReason as Reason, ContainerProfile,
    ContainerPurpose, VerificationSource,
};
use ciborium::value::Value;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn thumbprint_identity_length_placement_duplicates_and_critical_are_fixed_errors(
) -> Result<(), ContainerError> {
    let vectors = fixtures();
    let case = &vectors.cases[0];
    let key = key(case)?;
    let a = hex(&vectors.certificate_a);
    let suites = [suite(case)?];
    let payload = hex(&case.payload);
    let signature = hex(&case.signature);
    let trust = Trust {
        key: &key,
        certificate: &a,
    };
    let unprotected = hex(&case.unprotected);
    for (protected, unprotected, reason) in [
        (
            map(vec![
                (int(1), int(-7)),
                (
                    int(34),
                    Value::Array(vec![int(-7), Value::Bytes(vec![0; 32])]),
                ),
            ]),
            unprotected.clone(),
            Reason::ThumbprintAlgorithm,
        ),
        (
            map(vec![
                (int(1), int(-7)),
                (
                    int(34),
                    Value::Array(vec![int(-16), Value::Bytes(vec![0; 31])]),
                ),
            ]),
            unprotected.clone(),
            Reason::ThumbprintLength,
        ),
        (
            map(vec![
                (int(1), int(-7)),
                (
                    int(34),
                    Value::Array(vec![int(-16), Value::Bytes(vec![0; 32])]),
                ),
            ]),
            unprotected.clone(),
            Reason::CertificateMismatch,
        ),
        (
            map(vec![(int(1), int(-7)), (int(1), int(-7))]),
            unprotected.clone(),
            Reason::Duplicate,
        ),
        (
            map(vec![(int(1), int(-7)), (int(33), Value::Bytes(a.clone()))]),
            unprotected.clone(),
            Reason::Duplicate,
        ),
        (
            map(vec![
                (int(1), int(-7)),
                (int(2), Value::Array(vec![int(34)])),
            ]),
            unprotected.clone(),
            Reason::Critical,
        ),
        (
            map(vec![(int(1), int(-7))]),
            map(vec![
                (int(33), Value::Bytes(a.clone())),
                (
                    int(34),
                    Value::Array(vec![int(-16), Value::Bytes(vec![0; 32])]),
                ),
            ]),
            Reason::Profile,
        ),
        (
            map(vec![(int(1), int(-7))]),
            map(vec![(int(33), Value::Array(vec![Value::Bytes(a.clone())]))]),
            Reason::Malformed,
        ),
        (
            map(vec![(int(1), int(-7))]),
            map(vec![(
                int(33),
                Value::Array(vec![Value::Bytes(a.clone()), int(1)]),
            )]),
            Reason::Malformed,
        ),
    ] {
        let encoded = envelope(&protected, &unprotected, Some(&payload), &signature);
        assert_error(
            verify_container(
                request(&encoded, &payload, policy(case), &suites),
                VerificationSource::Certificates(&trust),
            ),
            reason,
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn strict_rfc9360_never_inherits_iso_unprotected_chain_exception() -> Result<(), ContainerError> {
    let vectors = fixtures();
    let case = &vectors.cases[9];
    let key = key(case)?;
    let suites = [suite(case)?];
    let a = hex(&vectors.certificate_a);
    let trust = Trust {
        key: &key,
        certificate: &a,
    };
    let payload = hex(&case.payload);
    let protected = map(vec![(int(1), int(-9))]);
    let encoded = envelope(
        &protected,
        &hex(&case.unprotected),
        Some(&payload),
        &hex(&case.signature),
    );
    assert_error(
        verify_container(
            request(&encoded, &payload, policy(case), &suites),
            VerificationSource::Certificates(&trust),
        ),
        Reason::Profile,
    );
    let original = hex(&case.encoded);
    let mut req = request(&original, &payload, policy(case), &suites);
    req.policy.profile = ContainerProfile::IsoEdition2Dis;
    assert_error(
        verify_container(req, VerificationSource::Certificates(&trust)),
        Reason::Profile,
    );
    let issuer = &vectors.cases[1];
    let ikey = super::support::key(issuer)?;
    let isuite = [suite(issuer)?];
    let encoded = hex(&issuer.encoded);
    assert_error(
        verify_container(
            request(&encoded, &hex(&issuer.payload), policy(issuer), &isuite),
            VerificationSource::Key(&ikey),
        ),
        Reason::Profile,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn protected_chain_revocation_rical_and_unprotected_vical_are_distinct(
) -> Result<(), ContainerError> {
    let vectors = fixtures();
    for index in [3, 4, 5] {
        let case = &vectors.cases[index];
        let key = key(case)?;
        let suites = [suite(case)?];
        let a = hex(&vectors.certificate_a);
        let trust = Trust {
            key: &key,
            certificate: &a,
        };
        let payload = hex(&case.payload);
        let encoded = hex(&case.encoded);
        let mut req = request(&encoded, &payload, policy(case), &suites);
        req.policy.purpose = if index == 4 {
            ContainerPurpose::Rical
        } else {
            ContainerPurpose::Vical
        };
        assert_error(
            verify_container(req, VerificationSource::Certificates(&trust)),
            Reason::Profile,
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn truncated_trailing_oversized_and_certificate_limits_are_checked() -> Result<(), ContainerError> {
    let vectors = fixtures();
    let case = &vectors.cases[0];
    let key = key(case)?;
    let suites = [suite(case)?];
    let a = hex(&vectors.certificate_a);
    let trust = Trust {
        key: &key,
        certificate: &a,
    };
    let payload = hex(&case.payload);
    let encoded = hex(&case.encoded);
    for size in 0..encoded.len() {
        assert!(verify_container(
            request(&encoded[..size], &payload, policy(case), &suites),
            VerificationSource::Certificates(&trust)
        )
        .is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_error(
        verify_container(
            request(&trailing, &payload, policy(case), &suites),
            VerificationSource::Certificates(&trust),
        ),
        Reason::Malformed,
    );
    let mut req = request(&encoded, &payload, policy(case), &suites);
    req.limits.encoded_bytes = encoded.len() - 1;
    assert_error(
        verify_container(req, VerificationSource::Certificates(&trust)),
        Reason::Limit,
    );
    let mut req = request(&encoded, &payload, policy(case), &suites);
    req.limits.payload_bytes = payload.len() - 1;
    assert_error(
        verify_container(req, VerificationSource::Certificates(&trust)),
        Reason::Limit,
    );
    for chain in [
        Value::Bytes(vec![1; 16_385]),
        Value::Array(vec![Value::Bytes(vec![1]); 9]),
        Value::Array(vec![Value::Bytes(vec![1; 16_384]); 5]),
    ] {
        let unprotected = map(vec![(int(33), chain)]);
        let bad = envelope(
            &hex(&case.protected),
            &unprotected,
            Some(&payload),
            &hex(&case.signature),
        );
        assert_error(
            verify_container(
                request(&bad, &payload, policy(case), &suites),
                VerificationSource::Certificates(&trust),
            ),
            Reason::Limit,
        );
    }
    Ok(())
}
