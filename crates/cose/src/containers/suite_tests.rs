// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{assert_error, hex};
use crate::containers::{
    verify_container, ContainerContent, ContainerError, ContainerErrorReason as Reason,
    ContainerLimits, ContainerPolicy, ContainerProfile, ContainerPurpose, ContainerVerifyRequest,
    CryptoVerificationKey, EnvelopePolicy, SignatureSuite, VerificationKey, VerificationSource,
};
use crate::iso18013::{Iso18013SignatureAlgorithm as Alg, Iso18013SignatureCurve as Curve};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vectors {
    schema: String,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    algorithm: i64,
    curve: i64,
    public: String,
    protected: String,
    payload: String,
    signature: String,
    structure: String,
    encoded: String,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn independent_original_and_modern_registrations_execute_without_substitution(
) -> Result<(), ContainerError> {
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../tests/fixtures/signature-suites.json"))
            .map_err(|_| Reason::Malformed)?;
    assert_eq!(vectors.schema, "reallyme.cose.signature-suites.v1");
    assert_eq!(vectors.cases.len(), 13);
    for case in vectors.cases {
        let modern = matches!(case.algorithm, -9 | -51 | -52 | -19);
        let suite = if modern {
            SignatureSuite::modern(crate::CoseSignatureAlgorithm::from_identifier(
                case.algorithm,
            )?)?
        } else {
            SignatureSuite::iso(
                Alg::from_identifier(case.algorithm)?,
                Curve::from_identifier(case.curve)?,
            )?
        };
        let public = hex(&case.public);
        crate::containers::validate_cose_signature(suite.curve(), &hex(&case.signature))?;
        let key = CryptoVerificationKey::new(suite, zeroize::Zeroizing::new(public), [0x37; 32]);
        if !matches!(case.curve, 1..=3 | 6) {
            assert_error(key, Reason::Provider);
            continue;
        }
        let key = key?;
        key.verify(&hex(&case.structure), &hex(&case.signature))?;
        let encoded = hex(&case.encoded);
        let payload = hex(&case.payload);
        let suites = [suite];
        let result = verify_container(
            ContainerVerifyRequest {
                encoded: &encoded,
                content: ContainerContent::Detached(&payload),
                external_aad: &[],
                policy: ContainerPolicy {
                    profile: if modern {
                        ContainerProfile::Rfc9360
                    } else {
                        ContainerProfile::IsoEdition2Dis
                    },
                    purpose: if modern {
                        ContainerPurpose::Generic
                    } else {
                        ContainerPurpose::DeviceAuthentication
                    },
                    envelope: EnvelopePolicy::Untagged,
                },
                allowed_suites: &suites,
                limits: ContainerLimits::default(),
            },
            VerificationSource::Key(&key),
        )?;
        assert_eq!(result.suite(), suite);
        assert_eq!(result.protected_headers(), hex(&case.protected));
        assert_eq!(result.payload(), payload);
        let other = if modern {
            SignatureSuite::iso(
                match case.curve {
                    1 => Alg::Es256,
                    2 => Alg::Es384,
                    3 => Alg::Es512,
                    _ => Alg::EdDsa,
                },
                suite.curve(),
            )?
        } else {
            SignatureSuite::modern(match case.curve {
                1 => crate::CoseSignatureAlgorithm::Esp256,
                2 => crate::CoseSignatureAlgorithm::Esp384,
                3 => crate::CoseSignatureAlgorithm::Esp512,
                _ => crate::CoseSignatureAlgorithm::Ed25519,
            })?
        };
        assert_ne!(
            other.registration().identifier(),
            suite.registration().identifier()
        );
        let wrong =
            CryptoVerificationKey::new(other, zeroize::Zeroizing::new(hex(&case.public)), [0; 32])?;
        assert_error(
            verify_container(
                ContainerVerifyRequest {
                    encoded: &encoded,
                    content: ContainerContent::Detached(&payload),
                    external_aad: &[],
                    policy: result.policy(),
                    allowed_suites: &[suite, other],
                    limits: ContainerLimits::default(),
                },
                VerificationSource::Key(&wrong),
            ),
            Reason::KeyAlgorithmMismatch,
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_suite_projection_cannot_bypass_container_profile_authorization(
) -> Result<(), ContainerError> {
    use crate::api::contract as wire;
    for (algorithm, curve, profile, purpose, expected) in [
        (
            wire::CoseSignatureAlgorithm::Es256,
            wire::CoseNamedCurve::P384,
            ContainerProfile::Iso2021,
            ContainerPurpose::ReaderAuthentication,
            Reason::Algorithm,
        ),
        (
            wire::CoseSignatureAlgorithm::Esp256,
            wire::CoseNamedCurve::P384,
            ContainerProfile::Rfc9360,
            ContainerPurpose::Generic,
            Reason::KeyAlgorithmMismatch,
        ),
        (
            wire::CoseSignatureAlgorithm::EcdsaSecp256k1Sha256,
            wire::CoseNamedCurve::Secp256k1,
            ContainerProfile::Rfc9360,
            ContainerPurpose::Generic,
            Reason::Algorithm,
        ),
    ] {
        let raw = wire::CoseSignatureSuite {
            registration: algorithm.into(),
            curve: curve.into(),
        };
        let projected = SignatureSuite::try_from(&raw)?;
        let policy = ContainerPolicy {
            profile,
            purpose,
            envelope: EnvelopePolicy::Untagged,
        };
        assert_error(policy.check(projected, false, false, &[]), expected);
    }
    Ok(())
}
