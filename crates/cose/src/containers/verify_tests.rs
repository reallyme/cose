// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{assert_error, envelope, fixtures, hex, key, policy, request, suite, Trust};
use crate::build_authentication_structure::{
    build_authentication_structure, AuthenticationContext,
};
use crate::containers::{
    verify_container, ContainerContent, ContainerError, ContainerErrorReason as Reason,
    ContainerProfile, ContainerPurpose, EndEntityIntegrity, EnvelopePolicy, VerificationSource,
};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn independent_container_answers_preserve_exact_bytes_and_key_binding() -> Result<(), ContainerError>
{
    let vectors = fixtures();
    let a = hex(&vectors.certificate_a);
    for case in &vectors.cases {
        let encoded = hex(&case.encoded);
        let payload = hex(&case.payload);
        let key = key(case)?;
        let trust = Trust {
            key: &key,
            certificate: &a,
        };
        let suites = [suite(case)?];
        let source = if case.id == "device" || case.id == "reader" || case.id == "reader-all" {
            VerificationSource::Key(&key)
        } else {
            VerificationSource::Certificates(&trust)
        };
        let result = verify_container(request(&encoded, &payload, policy(case), &suites), source)?;
        assert_eq!(result.encoded(), encoded);
        assert_eq!(result.protected_headers(), hex(&case.protected));
        assert_eq!(result.unprotected_headers(), hex(&case.unprotected));
        assert_eq!(result.payload(), payload);
        assert_eq!(result.verification_public_key(), hex(&case.public_key));
        assert_eq!(result.verification_context(), &[0x42; 32]);
        if result.selected_certificate_sha256().is_some() {
            assert_eq!(
                result.selected_certificate_sha256().map(|v| v.as_slice()),
                Some(hex(&vectors.certificate_a_sha256).as_slice())
            );
        }
        assert_eq!(result.policy(), policy(case));
        assert_eq!(
            *build_authentication_structure(
                AuthenticationContext::Signature1,
                &hex(&case.protected),
                &[],
                &payload
            )?,
            hex(&case.structure)
        );
        if case.id == "issuer-2021" {
            assert_eq!(
                result.provenance().end_entity_integrity,
                EndEntityIntegrity::IsoUnprotectedChain
            );
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn same_public_key_different_certificate_cannot_satisfy_x5t() -> Result<(), ContainerError> {
    let vectors = fixtures();
    let case = &vectors.cases[0];
    let key = key(case)?;
    let b = hex(&vectors.certificate_b);
    let trust = Trust {
        key: &key,
        certificate: &b,
    };
    let suites = [suite(case)?];
    let protected = hex(&case.protected);
    let payload = hex(&case.payload);
    let signature = hex(&case.signature);
    // Substitution leaves every signed byte and the signature unchanged. Both
    // certificates contain the same key, but the selected exact DER is different.
    let unprotected = super::support::map(vec![(
        super::support::int(33),
        ciborium::value::Value::Bytes(b.clone()),
    )]);
    let encoded = envelope(&protected, &unprotected, Some(&payload), &signature);
    assert_error(
        verify_container(
            request(&encoded, &payload, policy(case), &suites),
            VerificationSource::Certificates(&trust),
        ),
        Reason::CertificateMismatch,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn changed_payload_aad_header_signature_key_and_allowlist_fail() -> Result<(), ContainerError> {
    let vectors = fixtures();
    let case = &vectors.cases[6];
    let key = key(case)?;
    let suites = [suite(case)?];
    let encoded = hex(&case.encoded);
    let payload = hex(&case.payload);
    let mut changed = payload.clone();
    changed[0] ^= 1;
    assert_error(
        verify_container(
            request(&encoded, &changed, policy(case), &suites),
            VerificationSource::Key(&key),
        ),
        Reason::Authentication,
    );
    let mut aad_request = request(&encoded, &payload, policy(case), &suites);
    aad_request.external_aad = b"changed";
    assert_error(
        verify_container(aad_request, VerificationSource::Key(&key)),
        Reason::Profile,
    );
    let mut protected = hex(&case.protected);
    protected[2] = 0x38; // truncated negative algorithm argument
    let malformed = envelope(
        &protected,
        &hex(&case.unprotected),
        None,
        &hex(&case.signature),
    );
    assert_error(
        verify_container(
            request(&malformed, &payload, policy(case), &suites),
            VerificationSource::Key(&key),
        ),
        Reason::Malformed,
    );
    let mut signature = hex(&case.signature);
    signature[1] ^= 1;
    let bad = envelope(
        &hex(&case.protected),
        &hex(&case.unprotected),
        None,
        &signature,
    );
    assert_error(
        verify_container(
            request(&bad, &payload, policy(case), &suites),
            VerificationSource::Key(&key),
        ),
        Reason::Authentication,
    );
    assert_error(
        verify_container(
            request(&encoded, &payload, policy(case), &[]),
            VerificationSource::Key(&key),
        ),
        Reason::Algorithm,
    );
    let (wrong, _) = reallyme_crypto::dispatch::generate_keypair(crate::Algorithm::P256)
        .map_err(|_| Reason::Backend)?;
    let wrong = crate::containers::CryptoVerificationKey::new(
        suites[0],
        zeroize::Zeroizing::new(wrong),
        [0; 32],
    )?;
    assert_error(
        verify_container(
            request(&encoded, &payload, policy(case), &suites),
            VerificationSource::Key(&wrong),
        ),
        Reason::Authentication,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn attachment_tagging_registration_and_purpose_contracts_are_explicit() -> Result<(), ContainerError>
{
    let vectors = fixtures();
    let case = &vectors.cases[6];
    let key = key(case)?;
    let suites = [suite(case)?];
    let payload = hex(&case.payload);
    let encoded = hex(&case.encoded);
    let attached = envelope(
        &hex(&case.protected),
        &hex(&case.unprotected),
        Some(&payload),
        &hex(&case.signature),
    );
    assert_error(
        verify_container(
            request(&attached, &payload, policy(case), &suites),
            VerificationSource::Key(&key),
        ),
        Reason::Profile,
    );
    let mut req = request(&encoded, &payload, policy(case), &suites);
    req.content = ContainerContent::Attached;
    assert_error(
        verify_container(req, VerificationSource::Key(&key)),
        Reason::Profile,
    );
    let mut tagged = vec![0xd2];
    tagged.extend_from_slice(&encoded);
    assert_error(
        verify_container(
            request(&tagged, &payload, policy(case), &suites),
            VerificationSource::Key(&key),
        ),
        Reason::Profile,
    );
    let mut req = request(&encoded, &payload, policy(case), &suites);
    req.policy.profile = ContainerProfile::Iso2021;
    assert_error(
        verify_container(req, VerificationSource::Key(&key)),
        Reason::Profile,
    );
    let mut req = request(&encoded, &payload, policy(case), &suites);
    req.policy.envelope = EnvelopePolicy::Either;
    assert_error(
        verify_container(req, VerificationSource::Key(&key)),
        Reason::Profile,
    );
    // Changing the purpose is an explicit caller choice, never guessed from data.
    let mut req = request(&encoded, &payload, policy(case), &suites);
    req.policy.purpose = ContainerPurpose::ReaderAuthentication;
    assert_eq!(
        verify_container(req, VerificationSource::Key(&key))?
            .policy()
            .purpose,
        ContainerPurpose::ReaderAuthentication
    );
    Ok(())
}
