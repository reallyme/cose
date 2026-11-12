// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{assert_error, fixtures, hex, key, policy, request, suite};
use crate::containers::{
    sign_container, verify_container, CertificateHeaders, CertificateSelection,
    CertificateValidator, ContainerError, ContainerErrorReason as Reason, ContainerLimits,
    ContainerSignRequest, ContainerSigner, CryptoVerificationKey, SignatureEncoding,
    SigningContent, SigningInput, SigningMode, VerificationKey, VerificationSource,
};
use std::cell::Cell;
use zeroize::Zeroizing;

struct RejectCertificates {
    calls: Cell<usize>,
}
impl CertificateValidator for RejectCertificates {
    fn resolve(
        &self,
        _: &CertificateHeaders<'_>,
        _: i64,
    ) -> Result<CertificateSelection<'_>, ContainerError> {
        self.calls.set(self.calls.get() + 1);
        Err(Reason::CertificateValidation.into())
    }
}

struct RejectSigner {
    key: CryptoVerificationKey,
    calls: Cell<usize>,
    encoding: SignatureEncoding,
}
impl ContainerSigner for RejectSigner {
    fn verification_key(&self) -> &dyn VerificationKey {
        &self.key
    }
    fn input_mode(&self) -> SigningMode {
        SigningMode::Message
    }
    fn signature_encoding(&self) -> SignatureEncoding {
        self.encoding
    }
    fn sign(&self, _: SigningInput<'_>) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
        self.calls.set(self.calls.get() + 1);
        Err(Reason::Provider.into())
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn invalid_iso_policy_is_rejected_before_certificate_resolution() -> Result<(), ContainerError> {
    let vectors = fixtures();
    let case = &vectors.cases[0];
    let encoded = hex(&case.encoded);
    let payload = hex(&case.payload);
    let suites = [suite(case)?];
    let validator = RejectCertificates {
        calls: Cell::new(0),
    };
    let mut req = request(&encoded, &payload, policy(case), &suites);
    req.external_aad = b"not allowed";
    assert_error(
        verify_container(req, VerificationSource::Certificates(&validator)),
        Reason::Profile,
    );
    assert_eq!(validator.calls.get(), 0);
    let mut req = request(&encoded, &payload, policy(case), &suites);
    req.policy.envelope = crate::containers::EnvelopePolicy::Tagged;
    assert_error(
        verify_container(req, VerificationSource::Certificates(&validator)),
        Reason::Profile,
    );
    assert_eq!(validator.calls.get(), 0);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn output_limit_and_encoding_family_fail_before_signing() -> Result<(), ContainerError> {
    let vectors = fixtures();
    let case = &vectors.cases[6];
    let encoded = hex(&case.encoded);
    let protected = hex(&case.protected);
    let unprotected = hex(&case.unprotected);
    let payload = hex(&case.payload);
    let suites = [suite(case)?];
    let mut signer = RejectSigner {
        key: key(case)?,
        calls: Cell::new(0),
        encoding: SignatureEncoding::EcdsaFixed,
    };
    let req = |limit| ContainerSignRequest {
        protected_headers: &protected,
        unprotected_headers: &unprotected,
        content: SigningContent::Detached(&payload),
        external_aad: &[],
        policy: policy(case),
        allowed_suites: &suites,
        limits: ContainerLimits {
            encoded_bytes: limit,
            ..ContainerLimits::default()
        },
    };
    assert_error(
        sign_container(req(encoded.len() - 1), &signer),
        Reason::Limit,
    );
    assert_eq!(signer.calls.get(), 0);
    assert_error(
        sign_container(req(encoded.len()), &signer),
        Reason::Provider,
    );
    assert_eq!(signer.calls.get(), 1);
    signer.calls.set(0);
    signer.encoding = SignatureEncoding::EdDsa;
    assert_error(
        sign_container(req(encoded.len()), &signer),
        Reason::SignatureEncoding,
    );
    assert_eq!(signer.calls.get(), 0);
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn owned_public_key_is_not_duplicated_during_capability_construction() -> Result<(), ContainerError>
{
    let vectors = fixtures();
    let case = &vectors.cases[6];
    let suite = suite(case)?;
    drop(key(case)?); // Warm the crypto operation policy before measuring ownership.
    let public = Zeroizing::new(hex(&case.public_key));
    let mut result = None;
    let allocations = allocation_counter::measure(|| {
        result = Some(CryptoVerificationKey::new(suite, public, [0; 32]));
    });
    let key = result.ok_or(Reason::Backend)??;
    assert_eq!(key.public_key(), hex(&case.public_key));
    assert_eq!(allocations.count_total, 0);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn bad_signature_encoding_and_missing_chain_do_not_reach_certificate_validation(
) -> Result<(), ContainerError> {
    let vectors = fixtures();
    let case = &vectors.cases[0];
    let payload = hex(&case.payload);
    let suites = [suite(case)?];
    let validator = RejectCertificates {
        calls: Cell::new(0),
    };
    let encoded = super::support::envelope(
        &hex(&case.protected),
        &hex(&case.unprotected),
        Some(&payload),
        &[1],
    );
    assert_error(
        verify_container(
            request(&encoded, &payload, policy(case), &suites),
            VerificationSource::Certificates(&validator),
        ),
        Reason::SignatureEncoding,
    );
    assert_eq!(validator.calls.get(), 0);
    let encoded = super::support::envelope(
        &hex(&case.protected),
        &[0xa0],
        Some(&payload),
        &hex(&case.signature),
    );
    assert_error(
        verify_container(
            request(&encoded, &payload, policy(case), &suites),
            VerificationSource::Certificates(&validator),
        ),
        Reason::Profile,
    );
    assert_eq!(validator.calls.get(), 0);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn oversized_attached_result_is_rejected_before_signing() -> Result<(), ContainerError> {
    use crate::containers::{
        ContainerPolicy, ContainerProfile, ContainerPurpose, EnvelopePolicy, SignatureSuite,
    };
    let vectors = fixtures();
    let case = &vectors.cases[9];
    let suite = SignatureSuite::modern(crate::CoseSignatureAlgorithm::Esp256)?;
    let signer = RejectSigner {
        key: key(case)?,
        calls: Cell::new(0),
        encoding: SignatureEncoding::EcdsaFixed,
    };
    let protected = super::support::map(vec![(super::support::int(1), super::support::int(-9))]);
    let payload = vec![0; crate::limits::MAX_COSE_SIGN1_BYTES];
    let req = ContainerSignRequest {
        protected_headers: &protected,
        unprotected_headers: &[0xa0],
        content: SigningContent::Attached(&payload),
        external_aad: &[],
        policy: ContainerPolicy {
            profile: ContainerProfile::Rfc9360,
            purpose: ContainerPurpose::Generic,
            envelope: EnvelopePolicy::Untagged,
        },
        allowed_suites: &[suite],
        limits: ContainerLimits::default(),
    };
    assert_error(sign_container(req, &signer), Reason::Limit);
    assert_eq!(signer.calls.get(), 0);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn envelope_size_matches_independent_frames_and_checks_overflow() -> Result<(), ContainerError> {
    use crate::containers::measure_envelope::measure_envelope;
    for case in fixtures().cases {
        let attached = !matches!(case.id.as_str(), "reader" | "reader-all" | "device");
        let measured = measure_envelope(
            hex(&case.protected).len(),
            hex(&case.unprotected).len(),
            attached.then_some(hex(&case.payload).len()),
            hex(&case.signature).len(),
            false,
        )?;
        assert_eq!(measured, hex(&case.encoded).len());
    }
    for (length, expected) in [
        (0, 74),
        (23, 97),
        (24, 99),
        (255, 330),
        (256, 332),
        (65_535, 65_611),
        (65_536, 65_614),
    ] {
        assert_eq!(measure_envelope(3, 1, Some(length), 64, true)?, expected);
    }
    for (protected, unprotected, payload, signature) in [
        (usize::MAX, 0, None, 64),
        (3, usize::MAX, None, 64),
        (3, 1, Some(usize::MAX), 64),
        (3, 1, None, usize::MAX),
    ] {
        assert_error(
            measure_envelope(protected, unprotected, payload, signature, false),
            Reason::Limit,
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn malformed_content_type_is_rejected_before_certificate_resolution() -> Result<(), ContainerError>
{
    use ciborium::value::Value;
    let vectors = fixtures();
    let case = &vectors.cases[0];
    let payload = hex(&case.payload);
    let suites = [suite(case)?];
    let validator = RejectCertificates {
        calls: Cell::new(0),
    };
    for text in [
        "",
        "application",
        "/cbor",
        "application/",
        " application/cbor",
        "application/cbor ",
        "application/cbor; charset=utf-8",
        "application//cbor",
        "application/*",
        "åpplication/cbor",
    ] {
        let protected = super::support::map(vec![
            (super::support::int(1), super::support::int(-7)),
            (super::support::int(3), Value::Text(text.into())),
        ]);
        let encoded = super::support::envelope(
            &protected,
            &hex(&case.unprotected),
            Some(&payload),
            &hex(&case.signature),
        );
        assert_error(
            verify_container(
                request(&encoded, &payload, policy(case), &suites),
                VerificationSource::Certificates(&validator),
            ),
            Reason::Malformed,
        );
        assert_eq!(validator.calls.get(), 0);
    }
    for content_type in [
        Value::Text("application/cbor".into()),
        Value::Text("application/vnd.example+cbor".into()),
        super::support::int(60),
    ] {
        let protected = super::support::map(vec![
            (super::support::int(1), super::support::int(-7)),
            (super::support::int(3), content_type),
        ]);
        let encoded = super::support::envelope(
            &protected,
            &hex(&case.unprotected),
            Some(&payload),
            &hex(&case.signature),
        );
        assert_error(
            verify_container(
                request(&encoded, &payload, policy(case), &suites),
                VerificationSource::Certificates(&validator),
            ),
            Reason::CertificateValidation,
        );
    }
    assert_eq!(validator.calls.get(), 3);
    Ok(())
}
